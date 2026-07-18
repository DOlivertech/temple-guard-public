"""Bounded, read-only API posture testing for a web API you own or are authorized to test.

Two phases, both hard-capped and strictly non-destructive:

  1. ``discover_endpoints(base_url)`` — learn what an API exposes by first fetching a
     machine-readable spec at common locations (``/openapi.json``, ``/swagger.json``,
     ``/api-docs``, ``/v3/api-docs``, ``/openapi.yaml``) and parsing its paths+methods.
     If no spec is served, it probes a small fixed list of common API paths.
     Returns ``[{"method", "path", "source"}]``.

  2. ``test_endpoints(base_url, endpoints, max=…)`` — for a bounded subset, send ONE
     benign request per endpoint (GET, plus an OPTIONS on a couple) and flag posture
     issues: missing auth on sensitive paths, verbose errors / stack traces, weak CORS,
     risky methods, server/version disclosure, missing API security headers.

Nothing here writes, fuzzes, floods, brute-forces, or exploits. Only GET / OPTIONS /
HEAD, short per-request timeouts, and a global request budget (~40). Authorized-use only.

``run_api_test()`` orchestrates both and returns a ``checks.ScanResult`` so the existing
``report`` / ``monitor`` rendering works unchanged (it also emits the same ``on_event``
progress protocol as ``checks.scan``).
"""
from __future__ import annotations

import re
from typing import Callable, Optional
from urllib.parse import urlparse

import httpx

from .checks import Finding, ScanResult, SEV_RANK

__all__ = ["discover_endpoints", "test_endpoints", "run_api_test"]

# ---- bounds (everything here is hard-capped) --------------------------------
MAX_TOTAL_REQUESTS = 40      # global ceiling across discover + test in run_api_test()
MAX_TEST_ENDPOINTS = 12      # how many distinct endpoints we actually probe
MAX_OPTIONS = 3              # how many endpoints get an extra OPTIONS request
MAX_VERBOSE_FINDINGS = 3     # cap noisy stack-trace findings
DEFAULT_TIMEOUT = 8.0        # per-request seconds

# Machine-readable spec locations, in priority order.
SPEC_PATHS = ["/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs", "/openapi.yaml"]

# Fixed small list probed only when NO spec is found.
COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/v1", "/rest",
    "/health", "/healthz", "/status", "/version",
    "/users", "/user", "/me", "/admin", "/graphql",
]

HTTP_METHODS = ("get", "post", "put", "delete", "patch", "options", "head", "trace")
UA = {"User-Agent": "temple-guard/0.1 (+api-test; authorized self-scan)"}
CORS_PROBE_ORIGIN = "https://temple-guard-cors-probe.example"

# Path segments that suggest an endpoint returns/handles sensitive data.
SENSITIVE_KEYWORDS = (
    "user", "users", "admin", "account", "accounts", "token", "tokens",
    "secret", "secrets", "password", "credential", "credentials", "apikey",
    "config", "internal", "debug", "private", "order", "orders", "payment",
    "payments", "invoice", "invoices", "customer", "customers", "session",
    "sessions", "billing", "card", "cards", "ssn", "profile", "me", "role",
    "roles", "permission", "permissions", "key", "keys", "auth", "login",
    "logout", "register", "email", "phone", "address", "wallet", "transfer",
)
# Endpoints whose unauthenticated 200 is treated as high (bulk / listing data).
LISTY_SEGMENTS = (
    "users", "accounts", "customers", "orders", "payments", "admin",
    "secrets", "keys", "tokens", "credentials", "invoices", "sessions",
)

# Substrings that mark a leaked stack trace / internal error in a response body.
STACK_MARKERS = (
    "traceback (most recent call last)", ".py\", line", "  file \"",
    "at java.", "at org.springframework", "at javax.", "at com.sun.",
    "at system.", ".cs:line", "org.hibernate", "com.mysql", "java.lang.",
    "fatal error:", "<b>fatal error</b>", "undefined index", "undefined variable",
    "sqlalchemy.exc", "psycopg2.", "pymysql.err", "you have an error in your sql",
    "sqlstate[", "ora-0", "pg::", "werkzeug.exceptions", "django.core",
    "goroutine ", "panic: ", "runtime error:", "npgsql.", "microsoft.data.sqlclient",
)


# ---------------------------------------------------------------------------
# small shared helpers
# ---------------------------------------------------------------------------
class _Budget:
    """A hard cap on total HTTP requests, shared across discover + test."""

    def __init__(self, max_requests: int = MAX_TOTAL_REQUESTS) -> None:
        self.max = max_requests
        self.used = 0

    def available(self) -> bool:
        return self.used < self.max

    def spend(self) -> bool:
        if self.used >= self.max:
            return False
        self.used += 1
        return True


def _normalize(base_url: str) -> str:
    if "://" not in base_url:
        base_url = "https://" + base_url
    return base_url.rstrip("/")


def _client(timeout: float, verify: bool = True) -> httpx.Client:
    return httpx.Client(timeout=timeout, verify=verify, follow_redirects=True, headers=UA)


def _fill_params(path: str) -> str:
    """Replace path templating with a benign placeholder so a GET is well-formed.
    ``/users/{id}`` -> ``/users/1`` ; ``/users/:id`` -> ``/users/1``."""
    path = re.sub(r"\{[^/}]*\}", "1", path)
    path = re.sub(r"(?<=/):[^/]+", "1", path)
    return path


def _segments(path: str) -> list:
    return [s for s in path.lower().split("/") if s]


def _is_sensitive(path: str) -> bool:
    for seg in _segments(path):
        seg = re.sub(r"\{.*?\}", "", seg)
        for kw in SENSITIVE_KEYWORDS:
            if seg == kw or (len(kw) >= 5 and kw in seg):
                return True
    return False


def _looks_html(body: str) -> bool:
    head = body.lstrip()[:200].lower()
    return (head.startswith("<!doctype html") or head.startswith("<html")
            or "<head" in head or "<title" in head)


def _looks_like_data(body: str) -> bool:
    return body.lstrip()[:1] in ("{", "[")


# ---------------------------------------------------------------------------
# 1) discovery
# ---------------------------------------------------------------------------
def _spec_base_prefix(data: dict) -> str:
    """A path prefix implied by the spec (Swagger 2 basePath, or OpenAPI 3 server path)."""
    bp = data.get("basePath")
    if isinstance(bp, str) and bp not in ("", "/"):
        return bp.rstrip("/")
    servers = data.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        surl = servers[0].get("url", "")
        p = urlparse(surl).path if "://" in surl else surl
        if isinstance(p, str) and p and p != "/":
            return p.rstrip("/")
    return ""


def _parse_spec(data: dict, source: str) -> list:
    """Turn a parsed OpenAPI/Swagger doc into ``[{method, path, source}]``."""
    out: list = []
    if not isinstance(data, dict):
        return out
    paths = data.get("paths")
    if not isinstance(paths, dict):
        return out
    prefix = _spec_base_prefix(data)
    seen = set()
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        full = prefix + (path if path.startswith("/") else "/" + path)
        for method, _op in item.items():
            m = str(method).lower()
            if m in HTTP_METHODS:
                key = (m, full)
                if key not in seen:
                    seen.add(key)
                    out.append({"method": m.upper(), "path": full, "source": source})
    return out


def _parse_spec_yaml_text(text: str, source: str) -> list:
    """Best-effort YAML spec parse WITHOUT a PyYAML dependency: scan the ``paths:``
    block for ``/path:`` keys and their nested HTTP-method keys."""
    out: list = []
    seen = set()
    prefix = ""
    mbp = re.search(r'^\s*basePath:\s*["\']?(/[^\s"\']*)', text, re.M)
    if mbp:
        prefix = mbp.group(1).rstrip("/")
    in_paths = False
    paths_indent = 0
    current = None
    cur_indent = -1
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if not in_paths:
            if re.match(r'^paths:\s*(#.*)?$', line):
                in_paths = True
                paths_indent = indent
            continue
        if indent <= paths_indent and not stripped.startswith("/"):
            break  # left the paths block
        mp = re.match(r'^(/[^:]*):\s*(#.*)?$', stripped)
        if mp:
            current = mp.group(1)
            cur_indent = indent
            continue
        mm = re.match(r'^(get|post|put|delete|patch|options|head|trace):', stripped, re.I)
        if mm and current is not None and indent > cur_indent:
            m = mm.group(1).lower()
            full = prefix + current
            key = (m, full)
            if key not in seen:
                seen.add(key)
                out.append({"method": m.upper(), "path": full, "source": source})
    return out


def discover_endpoints(base_url: str, timeout: float = DEFAULT_TIMEOUT,
                       budget: Optional[_Budget] = None,
                       client: Optional[httpx.Client] = None) -> list:
    """Discover an API's endpoints. Returns ``[{"method", "path", "source"}]``.

    Strategy: fetch a machine-readable spec at the well-known locations and parse its
    paths + methods; if none is served, probe a small fixed list of common API paths.
    Bounded: at most ``len(SPEC_PATHS) + len(COMMON_API_PATHS)`` requests (default cap 20),
    each with a short timeout. Read-only (GET only).
    """
    base = _normalize(base_url)
    if budget is None:
        budget = _Budget(len(SPEC_PATHS) + len(COMMON_API_PATHS) + 1)
    own_client = client is None
    if client is None:
        client = _client(timeout)
    try:
        # (a) try to fetch + parse a spec
        for sp in SPEC_PATHS:
            if not budget.available():
                break
            budget.spend()
            try:
                r = client.get(base + sp)
            except httpx.HTTPError:
                continue
            if r.status_code != 200 or not r.content:
                continue
            source = "spec:" + sp
            ctype = r.headers.get("content-type", "").lower()
            body = r.text
            eps: list = []
            data = None
            try:
                data = r.json()
            except Exception:  # noqa: BLE001 — not JSON, fall through to YAML
                data = None
            if isinstance(data, dict) and isinstance(data.get("paths"), dict):
                eps = _parse_spec(data, source)
            elif sp.endswith((".yaml", ".yml")) or "yaml" in ctype or "yml" in ctype:
                try:
                    import yaml  # type: ignore  # optional; not a hard dependency
                    ydata = yaml.safe_load(body)
                    eps = _parse_spec(ydata, source) if isinstance(ydata, dict) else []
                except Exception:  # noqa: BLE001 — PyYAML missing/failed → regex fallback
                    eps = _parse_spec_yaml_text(body, source)
            if eps:
                return eps

        # (b) no spec — probe a small fixed list of common paths.
        # First fingerprint a bogus path: a server that 200s it is a catch-all
        # (SPA / framework fallback), so a 200 on a probed path proves nothing.
        catch_all = None  # (status, is_html, length)
        if budget.available():
            budget.spend()
            try:
                cr = client.get(base + "/__temple_guard_probe_404__")
                if cr.status_code != 404:
                    catch_all = (cr.status_code, _looks_html(cr.text[:400]), len(cr.content))
            except httpx.HTTPError:
                pass

        found: list = []
        seen = set()
        for p in COMMON_API_PATHS:
            if not budget.available():
                break
            budget.spend()
            try:
                r = client.get(base + p)
            except httpx.HTTPError:
                continue
            if r.status_code == 404 or p in seen:  # absent, or already seen
                continue
            if catch_all is not None and r.status_code == catch_all[0]:
                # server answers everything alike — skip responses that match the fallback
                if (_looks_html(r.text[:400]) and catch_all[1]) or abs(len(r.content) - catch_all[2]) <= 32:
                    continue
            seen.add(p)
            found.append({"method": "GET", "path": p, "source": "probe"})
        return found
    finally:
        if own_client:
            client.close()


# ---------------------------------------------------------------------------
# 2) per-endpoint posture checks
# ---------------------------------------------------------------------------
def _select(endpoints: list, limit: int) -> list:
    """Collapse to distinct paths and prioritise sensitive ones within the budget."""
    seen = set()
    uniq = []
    for ep in endpoints:
        p = ep.get("path", "")
        if not p or p in seen:
            continue
        seen.add(p)
        uniq.append(ep)

    def score(ep: dict) -> int:
        p = ep.get("path", "").lower()
        if _is_sensitive(p):
            return 0
        if any(k in p for k in ("health", "status", "version", "metrics", "admin")):
            return 1
        return 2

    uniq.sort(key=score)  # stable → keeps discovery order within a tier
    return uniq[:limit]


def _check_auth(path: str, r: httpx.Response, ctype: str, body: str,
                add: Callable[[Finding], None]) -> None:
    if not _is_sensitive(path):
        return
    if r.status_code in (401, 403):
        return  # good: auth enforced
    if r.status_code != 200 or not r.content:
        return
    if _looks_html(body):
        return  # SPA/login shell, not API data → avoid catch-all false positives
    if "json" not in ctype and not _looks_like_data(body):
        return
    listy = any(s in LISTY_SEGMENTS for s in _segments(path))
    sev = "high" if listy else "medium"
    add(Finding(
        f"Unauthenticated access to sensitive endpoint: {path}", sev, "auth",
        f"GET {r.request.url} -> {r.status_code} "
        f"({ctype or 'no content-type'}, {len(r.content)} bytes) with NO credentials sent.",
        "Require authentication/authorization on sensitive API routes and return 401/403 to "
        "anonymous callers. Also verify object-level authorization (no IDOR)."))


def _check_verbose_error(url: str, r: httpx.Response, body: str,
                         add: Callable[[Finding], None]) -> bool:
    low = body.lower()
    for marker in STACK_MARKERS:
        if marker in low:
            idx = low.find(marker)
            snippet = body[max(0, idx - 10): idx + 80].replace("\n", " ")
            add(Finding(
                "Verbose error / stack trace exposed", "medium", "disclosure",
                f"{url} -> {r.status_code}; body leaks internal error detail (…{snippet.strip()}…).",
                "Return generic error responses to clients and log stack traces server-side "
                "only. Disable framework debug mode in production."))
            return True
    return False


def _check_cors(url: str, hdr: dict, add: Callable[[Finding], None]) -> bool:
    acao = hdr.get("access-control-allow-origin", "")
    creds = hdr.get("access-control-allow-credentials", "").strip().lower() == "true"
    if not acao:
        return False
    if acao == CORS_PROBE_ORIGIN:
        if creds:
            add(Finding(
                "CORS reflects arbitrary Origin with credentials", "high", "cors",
                f"{url} echoed Origin '{CORS_PROBE_ORIGIN}' into Access-Control-Allow-Origin "
                f"AND set Access-Control-Allow-Credentials: true.",
                "Never reflect the caller's Origin while allowing credentials — this lets any "
                "site read authenticated responses. Allow-list exact trusted origins."))
        else:
            add(Finding(
                "CORS reflects arbitrary Origin", "medium", "cors",
                f"{url} echoed Origin '{CORS_PROBE_ORIGIN}' into Access-Control-Allow-Origin.",
                "Restrict Access-Control-Allow-Origin to an explicit allow-list instead of "
                "reflecting the request Origin."))
        return True
    if acao == "*" and creds:
        add(Finding(
            "CORS wildcard combined with credentials", "high", "cors",
            f"{url} set Access-Control-Allow-Origin: * together with Allow-Credentials: true.",
            "'*' with credentials is invalid and unsafe; specify exact trusted origins."))
        return True
    return False


def _check_headers(url: str, hdr: dict, ctype: str, add: Callable[[Finding], None]) -> None:
    if "x-content-type-options" not in hdr:
        add(Finding(
            "Missing API security header: X-Content-Type-Options", "low", "headers",
            f"Response from {url} did not include 'X-Content-Type-Options: nosniff'.",
            "Send X-Content-Type-Options: nosniff on API responses to stop MIME-type sniffing."))
    if "json" in ctype and "cache-control" not in hdr:
        add(Finding(
            "API JSON response has no Cache-Control", "low", "headers",
            f"{url} returned JSON without a Cache-Control header.",
            "Set Cache-Control: no-store on responses carrying sensitive data so it isn't cached."))


def _check_server(url: str, hdr: dict, add: Callable[[Finding], None]) -> None:
    srv = hdr.get("server", "")
    if srv and any(ch.isdigit() for ch in srv):
        add(Finding(
            f"Server version disclosed on API: {srv}", "low", "disclosure",
            f"Server: {srv} (from {url})",
            "Suppress version banners (Server / X-Powered-By) on API responses to slow recon."))
    xp = hdr.get("x-powered-by", "")
    if xp:
        add(Finding(
            f"Technology disclosed via X-Powered-By: {xp}", "low", "disclosure",
            f"X-Powered-By: {xp} (from {url})",
            "Remove the X-Powered-By header from API responses."))


def _check_methods(url: str, resp: httpx.Response, add: Callable[[Finding], None]) -> bool:
    allow = resp.headers.get("allow", "") or resp.headers.get("access-control-allow-methods", "")
    if not allow:
        return False
    up = allow.upper()
    dangerous = [m for m in ("TRACE", "CONNECT") if m in up]
    if dangerous:
        add(Finding(
            f"Dangerous HTTP methods advertised: {', '.join(dangerous)}", "medium", "methods",
            f"OPTIONS {url} -> Allow: {allow}",
            "Disable TRACE/CONNECT at the server/proxy — they enable cross-site tracing and "
            "tunnelling."))
    writey = [m for m in ("PUT", "DELETE", "PATCH") if m in up]
    add(Finding(
        f"API methods advertised via OPTIONS: {allow}",
        "info", "methods",
        f"OPTIONS {url} -> Allow: {allow}" + (f"  (state-changing: {', '.join(writey)})" if writey else ""),
        "Confirm state-changing methods (PUT/DELETE/PATCH) require authentication and "
        "authorization; only advertise the methods a route actually supports."))
    return True


def test_endpoints(base_url: str, endpoints: list, max: int = MAX_TEST_ENDPOINTS,
                   timeout: float = DEFAULT_TIMEOUT,
                   budget: Optional[_Budget] = None,
                   client: Optional[httpx.Client] = None,
                   on_finding: Optional[Callable[[Finding], None]] = None) -> list:
    """Send a bounded set of benign requests and return posture ``Finding``s.

    For up to ``max`` distinct endpoints (sensitive ones first) send ONE GET carrying a
    spoofed ``Origin`` (covering CORS reflection in the same request), plus an OPTIONS on a
    few endpoints to enumerate methods. Non-destructive: GET / OPTIONS only, never a body,
    hard-capped by ``budget`` (default 30 requests). Flags missing auth, verbose errors,
    weak CORS, risky methods, and server/version + missing-header disclosure.
    """
    base = _normalize(base_url)
    findings: list = []

    def add(f: Finding) -> None:
        findings.append(f)
        if on_finding:
            on_finding(f)

    if budget is None:
        budget = _Budget(MAX_TEST_ENDPOINTS * 2 + 6)
    own_client = client is None
    if client is None:
        client = _client(timeout)

    headers_reported = False
    server_reported = False
    cors_reported = False
    methods_reported = False
    verbose_count = 0
    options_used = 0

    try:
        for ep in _select(endpoints, max):
            if not budget.available():
                break
            path = ep.get("path", "/")
            test_path = _fill_params(path)
            if not test_path.startswith("/"):
                test_path = "/" + test_path
            url = base + test_path

            budget.spend()
            try:
                r = client.get(url, headers={"Origin": CORS_PROBE_ORIGIN})
            except httpx.HTTPError:
                continue
            hdr = {k.lower(): v for k, v in r.headers.items()}
            ctype = hdr.get("content-type", "").lower()
            body = r.text[:8000] if r.content else ""

            _check_auth(path, r, ctype, body, add)

            if verbose_count < MAX_VERBOSE_FINDINGS and _check_verbose_error(url, r, body, add):
                verbose_count += 1

            if not cors_reported and _check_cors(url, hdr, add):
                cors_reported = True

            if not server_reported:
                before = len(findings)
                _check_server(url, hdr, add)
                if len(findings) > before:
                    server_reported = True

            if not headers_reported and r.status_code < 500:
                _check_headers(url, hdr, ctype, add)
                headers_reported = True

            # OPTIONS on a few endpoints (method enumeration) — bounded
            if (options_used < MAX_OPTIONS and budget.available()
                    and (not methods_reported or _is_sensitive(path))):
                budget.spend()
                options_used += 1
                try:
                    o = client.request("OPTIONS", url, headers={"Origin": CORS_PROBE_ORIGIN})
                except httpx.HTTPError:
                    o = None
                if o is not None:
                    if not methods_reported and _check_methods(url, o, add):
                        methods_reported = True
                    if not cors_reported:
                        ohdr = {k.lower(): v for k, v in o.headers.items()}
                        if _check_cors(url, ohdr, add):
                            cors_reported = True
        return findings
    finally:
        if own_client:
            client.close()


# ---------------------------------------------------------------------------
# 3) orchestration → ScanResult (matches checks.scan's shape + event protocol)
# ---------------------------------------------------------------------------
def run_api_test(base_url: str, on_event: Optional[Callable[..., None]] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 max_requests: int = MAX_TOTAL_REQUESTS,
                 max_test: int = MAX_TEST_ENDPOINTS) -> ScanResult:
    """Discover + bounded-test an API and return a ``checks.ScanResult``.

    Mirrors ``checks.scan``: builds a ``ScanResult`` (so ``report``/``monitor`` render it
    unchanged) and, when ``on_event`` is given, streams the same protocol —
    ``on_event("step"|"finding"|"clean"|"unreachable", …)``. Everything is bounded by a
    single shared request budget (default 40) with short timeouts, and is read-only.

    The discovered endpoints are also attached as ``result.endpoints`` (a list of
    ``{method, path, source}``) for callers that want to show the discovery summary.
    """
    base = _normalize(base_url)
    res = ScanResult(url=base)
    res.endpoints = []  # type: ignore[attr-defined]  (extra attr; ignored by report)
    budget = _Budget(max_requests)

    def emit(kind: str, **kw) -> None:
        if on_event:
            on_event(kind, **kw)

    def add(f: Finding) -> None:
        res.findings.append(f)
        emit("finding", finding=f)

    client = _client(timeout)
    try:
        # root fetch — reachability + status/server, with a verify fallback (mirrors checks.scan)
        budget.spend()
        try:
            r0 = client.get(base)
        except httpx.HTTPError as exc:
            try:
                client.close()
                client = _client(timeout, verify=False)
                budget.spend()
                r0 = client.get(base)
            except Exception as exc2:  # noqa: BLE001
                res.reachable = False
                res.error = str(exc2 or exc)
                emit("unreachable", url=base, error=res.error)
                return res
        res.status = r0.status_code
        res.server = r0.headers.get("server", "")

        # phase 1 — discovery
        emit("step", category="tech", name="API discovery",
             desc="Fetch an OpenAPI/Swagger spec, else probe common API paths")
        eps = discover_endpoints(base, timeout=timeout, budget=budget, client=client)
        res.endpoints = eps  # type: ignore[attr-defined]
        if eps:
            src = str(eps[0].get("source", ""))
            emit("clean", category="tech",
                 name=f"API discovery — {len(eps)} endpoint(s) via {src.split(':', 1)[0]}")
            if src.startswith("spec:"):
                add(Finding(
                    "API specification publicly accessible", "info", "disclosure",
                    f"{base}{src.split(':', 1)[1]} served a machine-readable API spec "
                    f"({len(eps)} operations) to an anonymous client.",
                    "If the API isn't meant to be public, restrict the OpenAPI/Swagger document "
                    "(auth or network ACL) and ensure it doesn't leak internal-only routes."))
        else:
            emit("clean", category="tech", name="API discovery — no endpoints found")

        # phase 2 — bounded testing
        emit("step", category="methods", name="API endpoint testing",
             desc=f"Bounded read-only checks on up to {max_test} of {len(eps)} endpoint(s)")
        n0 = len(res.findings)
        test_endpoints(base, eps, max=max_test, timeout=timeout,
                       budget=budget, client=client, on_finding=add)
        if len(res.findings) == n0:
            emit("clean", category="methods", name="API endpoint testing")

        res.findings.sort(key=lambda f: SEV_RANK.get(f.severity, 9))
        return res
    finally:
        client.close()

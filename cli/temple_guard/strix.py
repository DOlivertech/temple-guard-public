"""Strix — autonomous vulnerability-validation engine (defensive orchestration).

Temple Guard does not vendor Strix; it **shells out** to a user-installed ``strix``
CLI (https://github.com/usestrix/strix, Apache-2.0) and turns its ``strix_runs/``
output into our own ``checks.Finding`` / ``checks.ScanResult`` so the same report
pipeline (``report.py``) renders it. Framed as **defensive validation**: it confirms
*real* weaknesses in an app you own or are authorized to test, proves they're
genuine, and hands you prioritized remediation — never "how we exploited you".

Two entry points:

* ``run_strix(target, …)`` — **launch** the engine live (private / hosted build only;
  gated by ``STRIX_CAN_LAUNCH``). Strix runs in its own Docker sandbox and validates
  by executing against the target, so this is consent-gated at the call site (§6.4).
* ``import_report(path)`` — **ingest** an existing ``strix_runs/`` output (both builds).
  Touches no target, needs no gate — it renders a report someone else produced.

**This build imports reports only** — ``STRIX_CAN_LAUNCH`` is False, so it never spawns
``strix``. Live, in-app validation is a hosted feature.

**Credentials** for the LLM that drives Strix come from the environment
(``STRIX_LLM`` + ``LLM_API_KEY``, optional ``LLM_API_BASE``) and are injected into the
subprocess **via env at spawn time — never on argv** (argv leaks in ``ps``) and never
logged (streamed output is redacted). ``config llm`` in the CLI writes them to
``~/.temple-guard/llm.json`` (chmod 600); this module merges that file with any real
env vars (env wins) when spawning.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

from .checks import Finding, ScanResult

# ── launch gate ────────────────────────────────────────────────────────────────
# This build imports reports only; live, in-app validation is a hosted feature.
STRIX_CAN_LAUNCH = False
MONITOR_VERB = "detect-only"

# ── credential storage (~/.temple-guard/llm.json, chmod 600) ───────────────────
TG_HOME = Path.home() / ".temple-guard"
LLM_CONFIG_PATH = TG_HOME / "llm.json"

# (key, label, default STRIX_LLM model id, provider key-page URL, needs api_base)
# The STRIX_LLM value is LiteLLM's `<provider>/<model>` form; these are sensible,
# fully-editable defaults — the user confirms/edits the exact model at `config llm`.
PROVIDERS = [
    ("anthropic", "Anthropic (Claude)", "anthropic/claude-opus-4-8",
     "https://console.anthropic.com/settings/keys", False),
    ("openai", "OpenAI", "openai/gpt-4o",
     "https://platform.openai.com/api-keys", False),
    ("google", "Google (Gemini / Vertex)", "gemini/gemini-1.5-pro",
     "https://aistudio.google.com/app/apikey", False),
    ("azure", "Azure OpenAI", "azure/<your-deployment>",
     "https://portal.azure.com/", True),
    ("bedrock", "AWS Bedrock", "bedrock/anthropic.claude-opus-4-8",
     "https://console.aws.amazon.com/bedrock/", False),
    ("local", "Local / Ollama", "ollama/llama3",
     None, True),
]
PROVIDER_KEYS = [p[0] for p in PROVIDERS]
# Providers where OAuth-first is the intended UX (Anthropic first — §4.2). Scaffold
# only for now; the key-paste path fully works for every provider.
OAUTH_FIRST = {"anthropic"}


def llm_config_path() -> Path:
    return LLM_CONFIG_PATH


def load_llm_config() -> dict:
    """Read the saved provider config, or {} if absent / unreadable."""
    try:
        return json.loads(LLM_CONFIG_PATH.read_text())
    except Exception:  # noqa: BLE001 — missing / malformed → treat as unconfigured
        return {}


def save_llm_config(cfg: dict) -> Path:
    """Persist the provider config at ~/.temple-guard/llm.json with 0600 perms.

    The API key is stored here (never committed, never logged). The directory is
    created 0700 and the file chmod'd 0600 so only the owner can read it."""
    TG_HOME.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(TG_HOME, stat.S_IRWXU)  # 0700
    except OSError:
        pass
    # Write then tighten perms before/after so the key is never briefly world-readable.
    LLM_CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(LLM_CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass
    return LLM_CONFIG_PATH


def llm_env(cfg: dict = None) -> dict:
    """Build the {STRIX_LLM, LLM_API_KEY, LLM_API_BASE} env Strix consumes.

    Starts from the saved config, then lets real environment variables override —
    so a user who exports LLM_API_KEY in their shell doesn't need `config llm`.
    Only non-empty values are included."""
    cfg = cfg if cfg is not None else load_llm_config()
    env: dict = {}
    model = cfg.get("model") or cfg.get("strix_llm")
    if model:
        env["STRIX_LLM"] = str(model)
    if cfg.get("api_key"):
        env["LLM_API_KEY"] = str(cfg["api_key"])
    if cfg.get("api_base"):
        env["LLM_API_BASE"] = str(cfg["api_base"])
    # Real env vars win (predictable + lets CI inject secrets without a file).
    for var in ("STRIX_LLM", "LLM_API_KEY", "LLM_API_BASE"):
        if os.environ.get(var):
            env[var] = os.environ[var]
    return env


def llm_status() -> tuple[bool, str]:
    """(configured, human summary) for `doctor` — never reveals the key itself."""
    env = llm_env()
    if not env.get("LLM_API_KEY"):
        return False, "no LLM provider connected"
    model = env.get("STRIX_LLM") or "(model not set)"
    src = "env" if os.environ.get("LLM_API_KEY") else "~/.temple-guard/llm.json"
    return True, f"{model}  ·  key from {src}"


# ── Strix install / preflight ──────────────────────────────────────────────────
def strix_path() -> Optional[str]:
    return shutil.which("strix")


def strix_version() -> tuple[bool, str]:
    """(installed, version-or-reason). Best-effort — `--version` support is 🔍 unverified."""
    exe = strix_path()
    if not exe:
        return False, "strix not found on PATH"
    try:
        p = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=15)
        out = (p.stdout or p.stderr).strip().splitlines()
        return True, (out[-1][:80] if out else "installed (version unknown)")
    except Exception:  # noqa: BLE001 — present but --version unsupported / errored
        return True, "installed (version check unavailable)"


def strix_hint() -> str:
    """Actionable install guidance, mirroring tools.docker_hint()."""
    return ("Install Strix — `pipx install strix-agent` (or `curl -sSL https://strix.ai/install | bash`). "
            "It runs the validation engine in its own Docker sandbox, so Docker must be running too. "
            "`doctor` can install it for you.")


def preflight(docker_ok: bool) -> list:
    """Rows for `doctor`'s Strix section: [(name, ok, detail, hint), …]."""
    installed, ver = strix_version()
    llm_ok, llm_detail = llm_status()
    return [
        ("strix installed", installed, ver, ("" if installed else strix_hint())),
        ("docker running", docker_ok, ("ready" if docker_ok else "not available"),
         ("" if docker_ok else "Strix needs Docker for its sandbox — start Docker Desktop / the daemon.")),
        ("LLM provider", llm_ok, llm_detail,
         ("" if llm_ok else "Connect a model provider:  temple-guard config llm")),
    ]


def install_strix() -> tuple[bool, str]:
    """Install Strix via pipx (isolated, on PATH). Returns (ok, message). Used by `doctor`."""
    import shutil
    pipx = shutil.which("pipx")
    if not pipx:
        return False, ("pipx not found — install pipx first (`python3 -m pip install --user pipx`), "
                       "then re-run `doctor`.")
    try:
        p = subprocess.run([pipx, "install", "strix-agent"], capture_output=True, text=True, timeout=900)
    except Exception as exc:  # noqa: BLE001
        return False, f"install did not start: {str(exc)[:80]}"
    blob = ((p.stdout or "") + (p.stderr or "")).lower()
    if p.returncode == 0 or "already seems to be installed" in blob:
        ok, ver = strix_version()
        return ok, (ver if ok else "installed — run `pipx ensurepath` and reopen your shell to get `strix` on PATH")
    tail = (p.stderr or p.stdout).strip().splitlines()
    return False, (tail[-1][:140] if tail else "`pipx install strix-agent` failed")


def pull_sandbox() -> tuple[bool, str]:
    """Pre-pull Strix's Docker sandbox image so the first validation isn't slow. (ok, message)."""
    import shutil
    docker = shutil.which("docker")
    if not docker:
        return False, "docker not found"
    try:
        p = subprocess.run([docker, "pull", SANDBOX_IMAGE], capture_output=True, text=True, timeout=1800)
    except Exception as exc:  # noqa: BLE001
        return False, f"pull did not start: {str(exc)[:80]}"
    if p.returncode == 0:
        return True, f"{SANDBOX_IMAGE} ready"
    tail = (p.stderr or p.stdout).strip().splitlines()
    return False, (tail[-1][:140] if tail else "pull failed")


# ── invocation builder (defensive framing; keys NEVER go on argv) ──────────────
# Source-verified against strix-agent 1.1.0.
SCAN_MODES = ("quick", "standard", "deep")   # Strix's OWN default is "deep"; WE default to "quick"
SCOPE_MODES = ("auto", "diff", "full")       # Strix default is "auto"

# Defensive containment for Strix's own sandbox (it carries no tg.* labels, §3.2).
# Values follow Docker conventions (mem/shm as <n>g, cpus/pids as numbers). Injected as
# defaults only — a user-exported STRIX_SANDBOX_* / STRIX_IMAGE / …_NETWORK always wins.
# 🔍 TODO: confirm the exact value formats against a live run. Network + image are left to
# Strix's own version-matched defaults (overriding either risks breaking target/LLM egress
# or pinning a stale sandbox image — STRIX_IMAGE default is ghcr.io/usestrix/strix-sandbox:1.0.0).
SANDBOX_IMAGE = "ghcr.io/usestrix/strix-sandbox:1.0.0"
_SANDBOX_ENV_DEFAULTS = {
    "STRIX_SANDBOX_MEM_LIMIT": "4g",
    "STRIX_SANDBOX_CPUS": "2",
    "STRIX_SANDBOX_PIDS_LIMIT": "512",
    "STRIX_SANDBOX_SHM_SIZE": "1g",
}


def strix_argv(target: str, *, scan_mode: str = "quick", scope_mode: str = None,
               diff_base: str = None, instruction: str = None, budget=None,
               mount: str = None, non_interactive: bool = True) -> list:
    """The exact `strix` command we would run. Credentials are injected via ENV at
    spawn, so they never appear here — argv is safe to print for --dry-run.

    Verified flags (strix-agent 1.1.0): --target/-t, -m/--scan-mode {quick,standard,deep}
    (Strix defaults deep; we pass quick), --scope-mode {auto,diff,full} + --diff-base,
    --max-budget-usd <n> (LLM cost cap), --mount <path> (read-only, local repos),
    --instruction, -n/--non-interactive."""
    argv = ["strix", "--target", target]
    mode = scan_mode if scan_mode in SCAN_MODES else "quick"
    argv += ["--scan-mode", mode]                 # always explicit — overrides Strix's deep default
    if scope_mode in SCOPE_MODES and scope_mode != "auto":
        argv += ["--scope-mode", scope_mode]
        if scope_mode == "diff" and diff_base:
            argv += ["--diff-base", diff_base]
    if mount:
        argv += ["--mount", str(mount)]
    if budget is not None:
        argv += ["--max-budget-usd", str(budget)]
    if instruction:
        argv += ["--instruction", instruction]
    if non_interactive:
        argv += ["-n"]  # headless; exit 2 = vulns found, 1 = error/interrupt, 0 = clean
    return argv


def redacted_env_display() -> dict:
    """The env we WOULD inject, with the key masked — for --dry-run only."""
    env = llm_env()
    out = dict(env)
    if out.get("LLM_API_KEY"):
        out["LLM_API_KEY"] = "***redacted***"
    return out


def _redactor(env: dict) -> Callable[[str], str]:
    """A line-scrubber that masks the API key (and anything key-shaped) in streamed
    output, so a live log can never leak the credential."""
    secrets = [v for k, v in env.items() if k in ("LLM_API_KEY",) and v]

    def scrub(line: str) -> str:
        for s in secrets:
            if s:
                line = line.replace(s, "***")
        # Belt-and-suspenders: mask obvious provider key shapes even if unset here.
        line = re.sub(r"sk-[A-Za-z0-9_\-]{12,}", "sk-***", line)
        return line

    return scrub


# on_event(kind, **data): kind in {"phase","line","finding","done","error"}.
EventFn = Optional[Callable[..., None]]

# Best-effort phase labels derived from Strix stdout keywords (defensive wording).
# TODO(strix-schema): confirm against a real run's actual log lines.
_PHASE_HINTS = [
    ("pulling sandbox image", ("pulling", "sandbox image", "downloading image", "pull complete")),
    ("scanning", ("recon", "reconnaissance", "scanning", "crawling", "mapping", "discovering")),
    ("validating", ("validat", "verifying", "confirming", "assessing", "testing")),
    ("writing report", ("writing report", "generating report", "summary", "strix_runs")),
]


def _phase_for(line: str) -> Optional[str]:
    low = line.lower()
    for label, needles in _PHASE_HINTS:
        if any(n in low for n in needles):
            return label
    return None


def _workdir() -> Path:
    d = TG_HOME / "strix"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _run_dirs(runs_root: Path) -> set:
    if not runs_root.is_dir():
        return set()
    return {p for p in runs_root.iterdir() if p.is_dir()}


def _newest_new_run(runs_root: Path, before: set) -> Optional[Path]:
    """The run dir Strix created this invocation — the newest dir added under strix_runs/
    since `before` (falls back to the newest existing dir). 🔍 TODO: run.json carries the
    canonical run metadata + generate_run_name() format; use it once a sample confirms the keys."""
    after = _run_dirs(runs_root)
    new_dirs = sorted(after - before, key=lambda p: p.stat().st_mtime)
    if new_dirs:
        return new_dirs[-1]
    return max(after, key=lambda p: p.stat().st_mtime) if after else None


def _terminate(proc: subprocess.Popen) -> None:
    """Best-effort stop. TODO(strix-sandbox): also tear down Strix's own sandbox
    container(s) on stop — they don't carry our labels, so reaping them needs a
    real run to learn the container naming (§3.2 / §6.7)."""
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception:  # noqa: BLE001
        pass


def run_strix(target: str, *, scan_mode: str = "quick", scope_mode: str = None,
              diff_base: str = None, instruction: str = None, budget=None,
              mount: str = None, on_event: EventFn = None, stop_event=None,
              timeout: int = 3600) -> ScanResult:
    """Launch Strix live against `target`, stream its activity, and parse the run
    into a ScanResult. **Private / hosted build only** — callers must check
    ``STRIX_CAN_LAUNCH`` and gate on consent (§6.4) before calling this.

    Emits, if `on_event` is given:
      * ("phase", name=…)     — a coarse progress phase changed
      * ("line", text=…)      — a (redacted) line of Strix output
      * ("finding", finding=) — a parsed finding (fired during post-run parsing)
      * ("error", message=…)  — the run failed
      * ("done", result=…)    — the run finished

    `stop_event` (threading.Event) requests cancellation (monitor 's'); the
    subprocess is terminated. Credentials are injected via env, never argv, and
    every streamed line is redacted."""
    def emit(kind: str, **kw) -> None:
        if on_event:
            on_event(kind, **kw)

    if not STRIX_CAN_LAUNCH:
        # Defensive by construction: without the private unlock we never spawn.
        raise RuntimeError(
            "Live Strix validation is a private-build / hosted feature. "
            "Use `strix import <strix_runs path>` to render an existing report.")

    env_extra = llm_env()
    if not env_extra.get("LLM_API_KEY"):
        raise RuntimeError(
            "No LLM provider connected. Run `temple-guard config llm` first "
            "(or export STRIX_LLM + LLM_API_KEY).")

    exe = strix_path()
    if not exe:
        raise RuntimeError(strix_hint())

    argv = strix_argv(target, scan_mode=scan_mode, scope_mode=scope_mode,
                      diff_base=diff_base, instruction=instruction, budget=budget, mount=mount)
    argv[0] = exe  # absolute path; rest of argv unchanged (no secrets on it)

    workdir = _workdir()
    runs_root = workdir / "strix_runs"
    before = _run_dirs(runs_root)

    env = {**os.environ, **env_extra}          # key injected here, NOT on argv
    for _k, _v in _SANDBOX_ENV_DEFAULTS.items():
        env.setdefault(_k, _v)                 # defensive containment; user-exported values win
    scrub = _redactor(env_extra)

    emit("phase", name="pulling sandbox image")  # first run pulls the sandbox image
    try:
        proc = subprocess.Popen(
            argv, cwd=str(workdir), env=env, text=True, bufsize=1,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        raise RuntimeError(strix_hint())

    stopped = False
    last_phase = "pulling sandbox image"
    start = time.monotonic()
    try:
        for raw in iter(proc.stdout.readline, ""):
            if stop_event is not None and stop_event.is_set():
                stopped = True
                _terminate(proc)
                break
            if timeout and (time.monotonic() - start) > timeout:
                _terminate(proc)
                raise RuntimeError(f"strix timed out after {timeout}s")
            line = scrub(raw.rstrip("\n"))
            phase = _phase_for(line)
            if phase and phase != last_phase:
                last_phase = phase
                emit("phase", name=phase)
            if line:
                emit("line", text=line)
    finally:
        if proc.stdout:
            proc.stdout.close()
    rc = proc.wait()

    if stopped:
        res = ScanResult(url=target, server="strix", status=rc)
        res.error = "stopped"
        return res

    # Parse the run directory Strix just created (the newest dir added under strix_runs/).
    run_dir = _newest_new_run(runs_root, before)
    findings = _parse_run_dir(run_dir) if run_dir is not None else []
    # A clean exit (0) with only the parser's "nothing found" placeholder = genuinely clean.
    if rc == 0 and len(findings) == 1 and findings[0].severity == "info" \
            and findings[0].title.startswith("Strix run imported"):
        findings = []
    res = ScanResult(url=target, server="strix", status=rc, findings=findings)

    # Strix headless exit codes (strix-agent 1.1.0): 2 = vulns found, 1 = error/interrupt,
    # 0 = clean. Our own command exit stays "1 on high-sev" — this only shapes res.error.
    if rc == 1 and not findings:
        res.error = ("Strix exited with an error/interrupt. "
                     "Check the streamed log above (provider auth / Docker / scope / budget).")
        emit("error", message=res.error)
    elif rc == 2 and run_dir is None:
        res.error = "Strix reported findings (exit 2) but no strix_runs/ output was found to parse."
        emit("error", message=res.error)
    elif rc not in (0, 1, 2) and not findings:
        res.error = f"Strix exited {rc} with no parseable strix_runs/ output."
        emit("error", message=res.error)
    # rc == 0 → clean (no vulns); findings empty, no error.

    for f in findings:
        emit("finding", finding=f)
    emit("done", result=res)
    return res


# ── report importer (public + private) ─────────────────────────────────────────
def import_report(path) -> ScanResult:
    """Ingest an existing Strix ``strix_runs/`` output → ScanResult (remediation view).

    `path` may be a single run directory (``strix_runs/<run-name>/``), the
    ``strix_runs/`` parent (newest run is used), or a single findings file
    (.json / .md). Touches no target — this is the public build's only Strix path."""
    p = Path(path).expanduser()
    if not p.exists():
        res = ScanResult(url=str(p), server="strix")
        res.reachable = False
        res.error = f"no such path: {p}"
        return res

    run_dir = _resolve_run_dir(p)
    findings = _parse_run_dir(run_dir) if run_dir.is_dir() else _parse_finding_file(run_dir)
    target = _guess_target(run_dir) or str(run_dir)
    return ScanResult(url=target, server="strix", status=None, findings=findings)


def _resolve_run_dir(p: Path) -> Path:
    """Pick the directory (or file) to parse from whatever the user pointed at."""
    if p.is_file():
        return p
    # If this looks like the strix_runs/ parent (holds run subdirs), take the newest run.
    if p.name == "strix_runs" or any(c.is_dir() for c in p.iterdir()):
        subdirs = [c for c in p.iterdir() if c.is_dir()]
        # A single run dir usually contains files, not further run subdirs — only
        # descend when EVERY child is a directory (i.e. p really is the runs root).
        if subdirs and all(c.is_dir() for c in p.iterdir()):
            return max(subdirs, key=lambda c: c.stat().st_mtime)
    return p


# ── parser (source-verified against strix-agent 1.1.0) ──────────────────────────
#
# Run dir layout: <CWD>/strix_runs/<run-name>/ with the PRIMARY findings file
# `vulnerabilities.json` (a JSON ARRAY of finding dicts). Fallbacks, in order:
# `findings.sarif` (SARIF 2.1.0; the rich fields live under result.properties.strix),
# then a Markdown/text scrape (penetration_test_report.md / vulnerabilities/<id>.md).
# Also emitted but unused here: vulnerabilities.csv, run.json.
#
# vulnerabilities.json element fields (verified): id, title, severity
# (critical|high|medium|low|info), timestamp, target, description, impact,
# technical_analysis, evidence, assumptions, poc_description, poc_script_code,
# remediation_steps, fix_effort, fix_pr_body, cvss (float 0-10), cvss_breakdown,
# endpoint, method, cve, cwe ("CWE-79"), code_locations[], finding_class
# ("dynamic"|"dependency_cve"), dependency_metadata, agent_id, agent_name.
#
# 🔍 Residual TODO (needs a live run): run.json key set + generate_run_name() format,
# exact per-value formats of the STRIX_SANDBOX_* limits, and the sandbox container
# name for kill-on-stop.

_VULNS_FILE = "vulnerabilities.json"
_SARIF_FILE = "findings.sarif"
# Wrapper keys tolerated if vulnerabilities.json is ever an object; also legacy fallbacks.
_LIST_KEYS = ("vulnerabilities", "findings", "results", "items")
_TITLE_KEYS = ("title", "id", "name", "summary")
_SEV_KEYS = ("severity", "risk", "level")
_CVSS_KEYS = ("cvss", "cvss_score", "score", "base_score")
_EVIDENCE_KEYS = ("evidence", "poc_description", "impact", "technical_analysis", "description")
_FIX_KEYS = ("remediation_steps", "remediation", "fix", "recommendation", "mitigation")

# Strix `cwe` (e.g. "CWE-79") → our finding category (drives report.py CAT_ICON + control-linking).
_CWE_CATEGORY = {
    "79": "xss", "80": "xss", "83": "xss",
    "89": "injection", "564": "injection", "943": "injection", "917": "injection",
    "611": "injection", "1336": "injection", "94": "rce", "95": "rce",
    "77": "rce", "78": "rce", "502": "rce",
    "352": "csrf", "918": "ssrf",
    "639": "idor", "566": "idor", "284": "idor", "285": "idor", "863": "idor", "862": "idor",
    "287": "auth", "306": "auth", "798": "auth", "384": "auth", "522": "auth", "620": "auth",
    "200": "disclosure", "16": "disclosure", "209": "disclosure", "22": "disclosure", "548": "disclosure",
    "840": "bizlogic", "841": "bizlogic",
}
# Coarse title / finding_class keyword → category, when no CWE resolves.
_CATEGORY_MAP = {
    "idor": "idor", "insecure direct object": "idor", "bola": "idor", "access control": "idor",
    "authorization": "idor", "ssrf": "ssrf", "rce": "rce", "remote code": "rce",
    "command injection": "rce", "os command": "rce", "deserial": "rce",
    "sqli": "injection", "sql injection": "injection", "nosql": "injection", "injection": "injection",
    "ssti": "injection", "template injection": "injection", "xxe": "injection",
    "xss": "xss", "cross-site scripting": "xss", "csrf": "csrf", "cross-site request": "csrf",
    "prototype pollution": "injection",
    "auth": "auth", "authentication": "auth", "session": "auth", "credential": "auth",
    "business logic": "bizlogic", "logic flaw": "bizlogic",
    "misconfig": "disclosure", "disclosure": "disclosure", "information leak": "disclosure",
    "dependency": "cve", "outdated": "cve",
}


def _cvss_band(score) -> Optional[str]:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "high"      # critical folds into our top band
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "info"


def _norm_sev(raw) -> str:
    s = str(raw or "").strip().lower()
    if s in ("critical", "crit"):
        return "high"
    if s in ("high", "medium", "med", "moderate", "low", "info", "informational", "none"):
        return {"med": "medium", "moderate": "medium", "informational": "info", "none": "info"}.get(s, s)
    return ""


def _first(d: dict, keys) -> Optional[str]:
    for k in keys:
        if k in d and d[k] not in (None, "", [], {}):
            v = d[k]
            if isinstance(v, (list, tuple)):
                v = ", ".join(str(x) for x in v)
            elif isinstance(v, dict):
                v = json.dumps(v)
            return str(v)
    return None


def _category_for(raw: Optional[str], title: str) -> str:
    hay = f"{raw or ''} {title}".lower()
    for needle, cat in _CATEGORY_MAP.items():
        if needle in hay:
            return cat
    return "validation"


def _cwe_num(cwe) -> Optional[str]:
    if not cwe:
        return None
    m = re.search(r"(\d+)", str(cwe))
    return m.group(1) if m else None


def _refs(d: dict) -> str:
    """Compact CWE/CVE reference string for the evidence header."""
    parts = [str(d[k]) for k in ("cwe", "cve") if d.get(k)]
    return "  ".join(parts)


def _category_for_vuln(d: dict) -> str:
    """Category from cwe → finding_class → title keyword (per the coordinator's mapping)."""
    num = _cwe_num(d.get("cwe"))
    if num and num in _CWE_CATEGORY:
        return _CWE_CATEGORY[num]
    if str(d.get("finding_class") or "").lower() == "dependency_cve":
        return "cve"          # a known-vuln in a dependency (package advisory)
    return _category_for(str(d.get("finding_class") or ""), str(d.get("title") or ""))


def _finding_from_vuln(d: dict) -> Optional[Finding]:
    """Map one Strix vulnerabilities.json element → our Finding (strix-agent 1.1.0 schema;
    also tolerant of the SARIF `properties.strix` shape and legacy keys)."""
    if not isinstance(d, dict):
        return None
    title = str(d.get("title") or d.get("id") or _first(d, _TITLE_KEYS) or "Validated weakness").strip()
    sev = _norm_sev(d.get("severity") or _first(d, _SEV_KEYS))   # critical→high inside _norm_sev
    cvss = d.get("cvss")
    if cvss in (None, ""):
        cvss = _first(d, _CVSS_KEYS)
    if not sev:
        sev = _cvss_band(cvss) or "medium"
    cat = _category_for_vuln(d)

    endpoint = d.get("endpoint") or _first(d, ("url", "path", "location", "affected"))
    method = d.get("method")
    # evidence = endpoint+method, then the descriptive fields, then the PoC as a trailing block.
    ev: list = []
    if endpoint:
        ev.append(f"{(str(method) + ' ') if method else ''}{endpoint}".strip())
    for k in ("evidence", "poc_description", "impact", "technical_analysis", "description"):
        v = d.get(k)
        if v:
            ev.append(str(v))
    if not ev:
        leg = _first(d, _EVIDENCE_KEYS)
        if leg:
            ev.append(leg)
    poc = d.get("poc_script_code") or d.get("poc")
    if poc:
        ev.append(f"PoC:\n{poc}")
    head = "  ·  ".join(p for p in (f"CVSS {cvss}" if cvss not in (None, "") else "", _refs(d)) if p)
    evidence = ((head + "\n") if head else "") + "\n".join(ev)
    evidence = evidence.strip() or "(validated by Strix — see the strix_runs artifact for the PoC)"

    # remediation = remediation_steps (list → bullets), then fix_pr_body appended.
    rem = d.get("remediation_steps")
    if isinstance(rem, list):
        rem = "\n".join(f"- {x}" for x in rem)
    rem = str(rem if rem not in (None, "") else (_first(d, _FIX_KEYS) or "")).strip()
    if not rem:
        rem = "Review the Strix run's suggested fix and harden the affected endpoint/parameter."
    if d.get("fix_pr_body"):
        rem = f"{rem}\n\nSuggested PR:\n{d['fix_pr_body']}"

    if endpoint and str(endpoint) not in title:
        title = f"{title} — {endpoint}"
    return Finding(title=title[:200], severity=sev, category=cat,
                   evidence=evidence[:2000], remediation=rem[:2000])


def _findings_from_json(data) -> list:
    """Map decoded JSON → findings. Handles the vulnerabilities.json array, a wrapper
    object, or a single finding dict; delegates each element to _finding_from_vuln."""
    items = None
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for k in _LIST_KEYS:
            if isinstance(data.get(k), list):
                items = data[k]
                break
        if items is None:
            if any(k in data for k in _TITLE_KEYS + _SEV_KEYS + _CVSS_KEYS):
                items = [data]                                  # a single finding object
            else:
                items = [v for v in data.values() if isinstance(v, dict)]
    out: list = []
    for it in (items or []):
        f = _finding_from_vuln(it)
        if f is not None:
            out.append(f)
    return out


def _findings_from_vulns_json(text: str) -> list:
    """Parse vulnerabilities.json (the primary artifact — a JSON array of finding dicts)."""
    try:
        return _findings_from_json(json.loads(text))
    except Exception:  # noqa: BLE001 — malformed JSON
        return []


_SARIF_LEVEL_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _findings_from_sarif(text: str) -> list:
    """Parse findings.sarif (SARIF 2.1.0). Strix stows the rich per-finding data under
    each result's `properties.strix` (id/severity/cvss/cwe/cve/target/endpoint/method/
    impact/technical_analysis/remediation_steps/poc); fall back to the SARIF message/level."""
    try:
        data = json.loads(text)
    except Exception:  # noqa: BLE001
        return []
    out: list = []
    for run in (data.get("runs") or []):
        for res in (run.get("results") or []):
            if not isinstance(res, dict):
                continue
            strix = (res.get("properties") or {}).get("strix")
            merged = dict(strix) if isinstance(strix, dict) else {}
            merged.setdefault("title", _sarif_title(res))
            if not merged.get("severity"):
                merged["severity"] = _SARIF_LEVEL_SEV.get(str(res.get("level") or "").lower(), "")
            f = _finding_from_vuln(merged)
            if f is not None:
                out.append(f)
    return out


def _sarif_title(res: dict) -> str:
    msg = res.get("message")
    if isinstance(msg, dict) and msg.get("text"):
        return str(msg["text"])
    return str(res.get("ruleId") or "Validated weakness")


def _find_named(root: Path, name: str) -> Optional[Path]:
    """Shallowest file named `name` (case-insensitive) under `root`."""
    matches = [p for p in root.rglob("*") if p.is_file() and p.name.lower() == name.lower()]
    return min(matches, key=lambda p: len(p.parts)) if matches else None


def _parse_finding_file(path: Path) -> list:
    """Parse a single artifact pointed at directly: vulnerabilities.json (array),
    a .sarif file, other JSON, or a Markdown/text report."""
    try:
        text = path.read_text(errors="replace")
    except Exception:  # noqa: BLE001
        return []
    name = path.name.lower()
    if name.endswith(".sarif") or ("sarif" in text[:400].lower() and '"version"' in text[:400]):
        got = _findings_from_sarif(text)
        if got:
            return got
    if path.suffix.lower() == ".json" or text.lstrip()[:1] in ("{", "["):
        got = _findings_from_vulns_json(text)
        if got:
            return got
    return _scrape_text_report(text, source=path.name)


def _parse_run_dir(run_dir: Path) -> list:
    """Parse a strix_runs/<run-name>/ directory into findings (strix-agent 1.1.0):
      1. vulnerabilities.json  (primary — a JSON array).
      2. findings.sarif        (SARIF 2.1.0 fallback).
      3. a Markdown / text report (penetration_test_report.md / vulnerabilities/<id>.md).
      4. else a single info finding, so the run is never dropped."""
    if run_dir.is_file():
        return _parse_finding_file(run_dir)

    vjson = _find_named(run_dir, _VULNS_FILE)
    if vjson is not None:
        # vulnerabilities.json is authoritative — a successful parse (even an empty array,
        # i.e. a CLEAN run) ends the search; only a malformed file falls through to SARIF/md.
        try:
            data = json.loads(vjson.read_text(errors="replace"))
        except Exception:  # noqa: BLE001
            data = None
        if data is not None:
            return _dedupe(_findings_from_json(data))

    sarif = _find_named(run_dir, _SARIF_FILE)
    if sarif is None:
        sarifs = sorted(run_dir.rglob("*.sarif"), key=lambda p: len(p.parts))
        sarif = sarifs[0] if sarifs else None
    if sarif is not None:
        got = _findings_from_sarif(sarif.read_text(errors="replace"))
        if got:
            return _dedupe(got)

    # No structured output — try a Markdown/text report (penetration_test_report.md, etc.).
    for pat in ("*.md", "*.markdown", "*.txt", "*.log"):
        for rp in sorted(run_dir.rglob(pat)):
            scraped = _scrape_text_report(rp.read_text(errors="replace"), source=rp.name)
            if scraped:
                return scraped

    # Nothing parseable — don't drop the run silently.
    return [Finding(
        title="Strix run imported — findings not auto-parsed",
        severity="info", category="validation",
        evidence=f"Run directory: {run_dir} (no vulnerabilities.json / findings.sarif / report found).",
        remediation="Open the run directory to review Strix's findings, or re-run so it writes "
                    "vulnerabilities.json.")]


_MD_FINDING = re.compile(r"^\s{0,3}#{1,4}\s+(.*\S)")
_MD_SEV = re.compile(r"\b(critical|high|medium|low|info(?:rmational)?)\b", re.I)


def _scrape_text_report(text: str, source: str = "report") -> list:
    """Very light Markdown/text scrape: treat headings that carry a severity word as
    findings. Intentionally conservative — a real parser replaces this once we have a
    sample (TODO(strix-schema))."""
    out: list = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _MD_FINDING.match(line)
        if not m:
            continue
        title = m.group(1).strip()
        # Collect body up to (but NOT into) the next heading, so a section title never
        # borrows the severity of the section below it.
        body_lines: list = []
        for nxt in lines[i + 1:i + 8]:
            if _MD_FINDING.match(nxt):
                break
            body_lines.append(nxt)
        sm = _MD_SEV.search(title) or _MD_SEV.search(" ".join(body_lines))
        if not sm:
            continue  # heading with no severity → probably a section header, skip
        sev = _norm_sev(sm.group(1)) or "medium"
        body = "\n".join(l for l in body_lines if l.strip())[:600]
        out.append(Finding(
            title=re.sub(r"\s*[-–—:]?\s*%s\s*$" % re.escape(sm.group(1)), "", title, flags=re.I).strip()[:200] or title[:200],
            severity=sev, category=_category_for(None, title),
            evidence=(body or f"(from {source})")[:1000],
            remediation="Review the Strix report's remediation guidance for this finding."))
    return out


def _dedupe(findings: list) -> list:
    seen: set = set()
    out: list = []
    for f in findings:
        key = (f.title, f.severity)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _guess_target(run_dir: Path) -> Optional[str]:
    """Recover the tested target from the run's own metadata. Prefers run.json, then a
    vulnerabilities.json element's `target` (the array case), then any target-ish JSON key."""
    if run_dir.is_file():
        run_dir = run_dir.parent
    named: list = []
    for n in ("run.json", _VULNS_FILE):
        p = _find_named(run_dir, n)
        if p is not None:
            named.append(p)
    for jp in named + list(run_dir.rglob("*.json"))[:20]:
        try:
            data = json.loads(jp.read_text(errors="replace"))
        except Exception:  # noqa: BLE001
            continue
        if isinstance(data, list):
            for el in data:
                if isinstance(el, dict) and el.get("target"):
                    return str(el["target"])
        elif isinstance(data, dict):
            for k in ("target", "url", "host", "scope"):
                v = data.get(k)
                if isinstance(v, str) and v:
                    return v
    # SARIF-only runs carry the target under result.properties.strix.target.
    sarif = _find_named(run_dir, _SARIF_FILE)
    if sarif is None:
        sarifs = list(run_dir.rglob("*.sarif"))
        sarif = sarifs[0] if sarifs else None
    if sarif is not None:
        try:
            data = json.loads(sarif.read_text(errors="replace"))
            for run in (data.get("runs") or []):
                for res in (run.get("results") or []):
                    t = ((res.get("properties") or {}).get("strix") or {}).get("target")
                    if t:
                        return str(t)
        except Exception:  # noqa: BLE001
            pass
    return None

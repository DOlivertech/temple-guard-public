"""Clients, engagements & authorized scope — the address book of what you may test.

temple-guard only scans what you OWN or are explicitly authorized to assess. This module
lets you record that permission up front and then pick targets *from it*, so a scan can't
wander outside what you're cleared for:

    Client        the owner you're testing for            (id/slug · name · notes)
      └ Engagement   a scoped, authorized piece of work    (id/slug · name · authorized ·
           └ scope      the exact URLs / domains / hosts     rules-of-engagement · created)
                        you're allowed to point tools at

A **target** is one entry in an engagement's scope (a URL / domain / host string). A target
is *pickable* / *in-scope* only when its engagement is marked ``authorized=True`` **and** the
target matches one of that engagement's scope entries — that's the core guarantee this module
exists to enforce.

Storage is plain JSON under ``~/.temple-guard/clients/`` (one human-readable file per client,
named ``<slug>.json``) so it's easy to read, back up, diff, or hand-edit. Override the base
directory with the ``TG_CLIENTS_DIR`` environment variable (the tests point it at a throwaway
dir). No Docker, no network, no database — just the filesystem, the stdlib, and rich.

Public API
    add_client(name, notes="", slug=None) -> Client
    list_clients() -> list[Client]
    get_client(ref) -> Client | None
    add_engagement(client, name, scope=[...], authorized=False, roe="", created=None) -> Engagement
    list_engagements(client) -> list[Engagement]
    add_targets(client, engagement, targets) -> Engagement        # extend a scope
    set_authorized(client, engagement, authorized) -> Engagement
    all_targets(authorized_only=True) -> list[ScopedTarget]
    targets_for(client=None, engagement=None, authorized_only=True) -> list[ScopedTarget]
    in_scope(target, authorized_only=True) -> bool
    pick_target(console) -> str | None                            # interactive, rich/_pick
    manage(console) -> None                                       # interactive menu
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.text import Text

# Brand chrome — mirrors report.py's palette. Defined locally on purpose so this module stays
# dependency-light (stdlib + rich only) and importable in isolation, without pulling in the
# checks/httpx chain just for two colour strings.
BLUE = "#38bdf8"
PURPLE = "#a855f7"
AMBER = "#fbbf24"
RED = "#f87171"
GREEN = "#4ade80"
DIM = "#94a3b8"

DEFAULT_HOME = Path.home() / ".temple-guard" / "clients"

__all__ = [
    "Client", "Engagement", "ScopedTarget",
    "clients_dir", "add_client", "list_clients", "get_client",
    "add_engagement", "list_engagements", "get_engagement", "add_targets", "set_authorized",
    "all_targets", "targets_for", "in_scope",
    "pick_target", "manage", "overview",
]


# ── data model ──────────────────────────────────────────────────────────────
@dataclass
class Engagement:
    """A scoped, authorized piece of work under a client. Its targets are only ever pickable
    when ``authorized`` is True (you have written permission to test everything in ``scope``)."""
    slug: str
    name: str
    authorized: bool = False
    scope: List[str] = field(default_factory=list)   # allowed URLs / domains / hosts
    roe: str = ""                                     # rules-of-engagement note
    created: str = ""                                 # a date string, e.g. "2026-07-17"


@dataclass
class Client:
    """An owner you're testing for, holding one or more engagements."""
    slug: str
    name: str
    notes: str = ""
    engagements: List[Engagement] = field(default_factory=list)


@dataclass
class ScopedTarget:
    """One in-scope target flattened out with its owning client + engagement labels — what the
    pickers and `scan`/`monitor` integration consume."""
    target: str
    client_slug: str
    client_name: str
    engagement_slug: str
    engagement_name: str
    authorized: bool

    @property
    def label(self) -> str:
        return f"{self.client_name} / {self.engagement_name}"


# ── storage ─────────────────────────────────────────────────────────────────
def clients_dir() -> Path:
    """Directory where per-client JSON lives. Honours ``$TG_CLIENTS_DIR`` (tests point this at a
    throwaway dir); defaults to ``~/.temple-guard/clients``. Created on demand."""
    raw = os.environ.get("TG_CLIENTS_DIR")
    d = Path(raw).expanduser() if raw else DEFAULT_HOME
    d.mkdir(parents=True, exist_ok=True)
    return d


def _client_path(slug: str) -> Path:
    return clients_dir() / f"{slug}.json"


def _client_from_dict(d: dict) -> Client:
    engs = [
        Engagement(
            slug=e.get("slug") or _slugify(e.get("name", "engagement")),
            name=e.get("name", ""),
            authorized=bool(e.get("authorized", False)),
            scope=_dedupe(_clean_target(s) for s in e.get("scope", [])),
            roe=e.get("roe", ""),
            created=e.get("created", ""),
        )
        for e in d.get("engagements", [])
    ]
    return Client(
        slug=d.get("slug") or _slugify(d.get("name", "client")),
        name=d.get("name", ""),
        notes=d.get("notes", ""),
        engagements=engs,
    )


def _save(c: Client) -> Client:
    _client_path(c.slug).write_text(json.dumps(asdict(c), indent=2) + "\n")
    return c


def list_clients() -> List[Client]:
    """Every registered client, sorted by name. Unreadable/corrupt files are skipped, never fatal."""
    out: List[Client] = []
    for p in sorted(clients_dir().glob("*.json")):
        try:
            out.append(_client_from_dict(json.loads(p.read_text())))
        except Exception:
            continue
    out.sort(key=lambda c: c.name.lower())
    return out


def get_client(ref) -> Optional[Client]:
    """Fetch a client by slug (preferred), or fall back to a case-insensitive name match.
    Passing a Client returns it unchanged (so callers can hand us either)."""
    if isinstance(ref, Client):
        return ref
    if not ref:
        return None
    p = _client_path(str(ref))
    if p.exists():
        try:
            return _client_from_dict(json.loads(p.read_text()))
        except Exception:
            return None
    ref_l = str(ref).strip().lower()
    for c in list_clients():
        if c.slug == ref_l or c.name.lower() == ref_l:
            return c
    return None


def get_engagement(client, ref) -> Optional[Engagement]:
    """Find an engagement under a client by slug (preferred) or case-insensitive name."""
    c = get_client(client)
    if not c or not ref:
        return None
    r = ref.slug if isinstance(ref, Engagement) else str(ref).strip().lower()
    for e in c.engagements:
        if e.slug == r or e.name.lower() == r:
            return e
    return None


# ── mutations ───────────────────────────────────────────────────────────────
def add_client(name: str, notes: str = "", slug: Optional[str] = None) -> Client:
    """Register a client (owner). The slug is derived from the name (or an explicit `slug`) and
    de-duplicated against existing clients, so two 'Acme's become `acme` and `acme-2`."""
    name = (name or "").strip()
    if not name:
        raise ValueError("client name is required")
    existing = {p.stem for p in clients_dir().glob("*.json")}
    new_slug = _unique_slug(_slugify(slug or name), existing)
    return _save(Client(slug=new_slug, name=name, notes=(notes or "").strip()))


def add_engagement(client, name: str, scope=None, authorized: bool = False,
                   roe: str = "", created: Optional[str] = None,
                   slug: Optional[str] = None) -> Engagement:
    """Open an engagement under `client` (a slug or Client) with an authorized `scope`.

    scope       list of allowed URLs / domains / hosts (cleaned + de-duplicated)
    authorized  gates whether this engagement's targets are ever pickable / in-scope
    roe         free-text rules-of-engagement note
    created     a date string; defaults to today (YYYY-MM-DD) — pass your own to override
    """
    c = get_client(client)
    if c is None:
        raise ValueError(f"no such client: {client!r} — add_client(...) first")
    name = (name or "").strip()
    if not name:
        raise ValueError("engagement name is required")
    eslug = _unique_slug(_slugify(slug or name), {e.slug for e in c.engagements})
    eng = Engagement(
        slug=eslug,
        name=name,
        authorized=bool(authorized),
        scope=_dedupe(_clean_target(s) for s in (scope or [])),
        roe=(roe or "").strip(),
        created=(created or _today()),
    )
    c.engagements.append(eng)
    _save(c)
    return eng


def list_engagements(client) -> List[Engagement]:
    """Engagements under a client (slug or Client). Empty list if the client is unknown."""
    c = get_client(client)
    return list(c.engagements) if c else []


def add_targets(client, engagement, targets) -> Engagement:
    """Append one or more targets to an engagement's scope (a delta), de-duplicated. Persists."""
    c = get_client(client)
    if c is None:
        raise ValueError(f"no such client: {client!r}")
    e = get_engagement(c, engagement)
    if e is None:
        raise ValueError(f"no such engagement: {engagement!r}")
    if isinstance(targets, str):
        targets = [targets]
    e.scope = _dedupe(list(e.scope) + [_clean_target(t) for t in targets])
    _save(c)
    return e


def set_authorized(client, engagement, authorized: bool) -> Engagement:
    """Flip an engagement's authorization. Un-authorizing immediately drops its targets out of
    every picker / `in_scope` check — the authorization gate is evaluated live, not cached."""
    c = get_client(client)
    e = get_engagement(c, engagement) if c else None
    if e is None:
        raise ValueError("no such client / engagement")
    e.authorized = bool(authorized)
    _save(c)
    return e


# ── queries: targets & scope ────────────────────────────────────────────────
def targets_for(client=None, engagement=None, authorized_only: bool = True) -> List[ScopedTarget]:
    """Flattened in-scope targets with their client/engagement labels. Optionally filter by
    client and/or engagement (each a slug or object). By default only AUTHORIZED engagements
    contribute — the same rule that makes a target pickable."""
    cslug = client.slug if isinstance(client, Client) else client
    eslug = engagement.slug if isinstance(engagement, Engagement) else engagement
    out: List[ScopedTarget] = []
    for c in list_clients():
        if cslug and c.slug != cslug:
            continue
        for e in c.engagements:
            if eslug and e.slug != eslug:
                continue
            if authorized_only and not e.authorized:
                continue
            for s in e.scope:
                s = _clean_target(s)
                if s:
                    out.append(ScopedTarget(s, c.slug, c.name, e.slug, e.name, e.authorized))
    return out


def all_targets(authorized_only: bool = True) -> List[ScopedTarget]:
    """Every in-scope target across all clients + engagements (authorized only by default)."""
    return targets_for(authorized_only=authorized_only)


def in_scope(target: str, authorized_only: bool = True) -> bool:
    """True if `target` falls inside some engagement's scope. By default only AUTHORIZED
    engagements count — this is the gate `scan`/`monitor` should consult before touching a
    target the operator typed by hand."""
    t = _clean_target(target)
    if not t:
        return False
    for c in list_clients():
        for e in c.engagements:
            if authorized_only and not e.authorized:
                continue
            if any(_scope_match(t, s) for s in e.scope):
                return True
    return False


# ── scope matching (scheme-insensitive, port/path aware, simple wildcards) ───
def _split_target(t: str):
    """(host, port, path) for a URL / domain / host string — scheme + any creds stripped,
    lower-cased. 'https://beta.example.com/app' -> ('beta.example.com', '', '/app')."""
    t = _clean_target(t).lower()
    if "://" in t:
        t = t.split("://", 1)[1]
    if "@" in t.split("/", 1)[0]:            # strip user:pass@ if present
        t = t.split("@", 1)[1]
    hostport, _, path = t.partition("/")
    host, _, port = hostport.partition(":")
    return host, port, ("/" + path if path else "")


def _scope_match(target: str, scope_entry: str) -> bool:
    """Is `target` covered by a single `scope_entry`?  Comparison ignores the scheme and is:

    - a bare domain / host in scope (no port, no path) covers that host on any scheme/port/path
      — e.g. scope 'beta.example.com' matches 'https://beta.example.com/anything';
    - a '*.' wildcard covers subdomains — e.g. '*.example.com' matches 'api.example.com';
    - otherwise the host + port must match and the path must be equal or a sub-path
      — e.g. scope 'http://localhost:8000' matches 'localhost:8000' but not ':9000'.
    """
    th, tport, tpath = _split_target(target)
    sh, sport, spath = _split_target(scope_entry)
    if not sh or not th:
        return False
    if sh.startswith("*."):                       # wildcard subdomain
        base = sh[2:]
        return th == base or th.endswith("." + base)
    if not sport and not spath:                   # bare domain/host → any port/path on that host
        return th == sh
    if th != sh or tport != sport:                # else host + port must line up
        return False
    if spath in ("", "/"):                         # scope pins host:port only
        return True
    return tpath == spath or tpath.startswith(spath.rstrip("/") + "/")


# ── small helpers ───────────────────────────────────────────────────────────
def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return s or "item"


def _unique_slug(base: str, taken) -> str:
    taken = set(taken)
    slug, n = base, 2
    while slug in taken:
        slug, n = f"{base}-{n}", n + 1
    return slug


def _clean_target(t: str) -> str:
    """Light, human-readable cleanup of a scope entry / target: trim, drop a trailing slash.
    We keep whatever scheme (or none) the operator typed — matching is scheme-insensitive."""
    return (t or "").strip().rstrip("/")


def _dedupe(items) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for it in items:
        if it and it not in seen:
            seen.add(it)
            out.append(it)
    return out


def _today() -> str:
    try:
        return date.today().isoformat()
    except Exception:  # pragma: no cover — never let a clock quirk block registration
        return ""


# ── interactive: a _pick selector in the CLI's house style ──────────────────
def _pick(console: Console, message: str, items, default=None):
    """Fuzzy, type-to-filter selector — the same UX as cli.py's picker (InquirerPy fuzzy with a
    numbered rich fallback). `items` = [(value, label, desc)]. Esc / 'back' → None. Set
    ``TG_NO_FUZZY`` (or run without a TTY) to force the numbered fallback. Ctrl+C bubbles up."""
    if sys.stdin.isatty() and console.is_terminal and not os.environ.get("TG_NO_FUZZY"):
        try:
            from InquirerPy import inquirer
            from InquirerPy.base.control import Choice
            choices = [Choice(value=v, name=(f"{lbl}   ·   {d}" if d else lbl)) for v, lbl, d in items]
            return inquirer.fuzzy(
                message=message, choices=choices, border=True,
                max_height="70%", cycle=True, pointer="❯", qmark="›", amark="›",
                mandatory=False, keybindings={"skip": [{"key": "escape"}]},   # Esc → skip → None
                instruction="(type to filter · ↑↓ move · enter select)",
                long_instruction="Esc = back      Ctrl+C = quit",
            ).execute()
        except Exception:  # no fuzzy TTY / import issue → numbered fallback (Ctrl+C still bubbles)
            pass
    console.print(Text(f"\n{message}", style=f"bold {PURPLE}"))
    for i, (_v, lbl, d) in enumerate(items, 1):
        console.print(Text.assemble((f"  {i:>2}  ", f"bold {BLUE}"),
                                    (lbl.ljust(24) + "  ", "bold white"), (d, "dim")))
    console.print(Text("   b  ← back", style="dim"))
    keys = [str(i) for i in range(1, len(items) + 1)]
    dflt = "1" if keys else "b"
    if default is not None:                       # preselect the row whose VALUE == default
        for i, (v, _l, _d) in enumerate(items, 1):
            if v == default:
                dflt = str(i)
                break
    ans = Prompt.ask(f"[{BLUE}]Choose[/]", choices=keys + ["b"], default=dflt)
    return None if ans == "b" else items[int(ans) - 1][0]


def pick_target(console: Console) -> Optional[str]:
    """Interactively choose ONE authorized, in-scope target and return it as a string (or None
    if the operator backs out, or nothing is in scope yet). Type-to-filter spans the target and
    its client / engagement, so you can narrow by client name just by typing it — this is the
    'pick from your scoped targets' entry point for `scan` / `monitor`."""
    scoped = all_targets(authorized_only=True)
    if not scoped:
        console.print(Text.assemble(
            ("No authorized, in-scope targets yet.  ", f"bold {AMBER}"),
            ("Register a client + an authorized engagement first "
             "(the manage menu, or `temple-guard client` / `scope`).", "dim")))
        return None
    console.print(Text.assemble(
        ("Pick a scoped target  ", f"bold {PURPLE}"),
        (f"— {len(scoped)} authorized target(s) across your engagements", "dim")))
    items = [(st.target, st.target, st.label) for st in scoped]
    items.append(("__back__", "← Back", ""))
    choice = _pick(console, "Which target?", items)
    if not choice or choice == "__back__":
        return None
    return choice


# ── interactive: the manage menu + its sub-flows ────────────────────────────
def manage(console: Console) -> None:
    """A small interactive menu to create / list clients, engagements, and scope targets.
    'Done' or Esc exits. Every path reinforces the authorized-and-in-scope model."""
    while True:
        items = [
            ("list", "List clients & scope", "everything you've registered"),
            ("client", "New client", "register an owner you're testing for"),
            ("engagement", "New engagement", "an authorized, scoped piece of work under a client"),
            ("target", "Add scope targets", "extend an engagement's allowed target list"),
            ("auth", "Authorize / revoke", "flip whether an engagement's targets are pickable"),
            ("done", "Done", "back"),
        ]
        choice = _pick(console, "Manage clients & scope", items, default="list")
        if choice in (None, "done"):
            return
        console.print()
        if choice == "list":
            _print_overview(console)
        elif choice == "client":
            _new_client_flow(console)
        elif choice == "engagement":
            _new_engagement_flow(console)
        elif choice == "target":
            _add_target_flow(console)
        elif choice == "auth":
            _toggle_auth_flow(console)


def overview(console: Console) -> None:
    """Print the full clients → engagements → scope tree. The read-only render behind both the
    manage menu's 'List' item and a non-interactive `temple-guard client list`."""
    _print_overview(console)


def _print_overview(console: Console) -> None:
    clients = list_clients()
    if not clients:
        console.print(Text("No clients yet — create one to start scoping your engagements.", style="dim"))
        return
    console.print(Text("Clients & authorized scope", style=f"bold {PURPLE}"))
    for c in clients:
        n_auth = sum(1 for e in c.engagements if e.authorized)
        console.print(Text.assemble(
            ("  ● ", f"bold {BLUE}"), (c.name, "bold white"), (f"  [{c.slug}]", "dim"),
            (f"   {len(c.engagements)} engagement(s), {n_auth} authorized", "dim")))
        if c.notes:
            console.print(Text.assemble(("      ", ""), (c.notes, "dim italic")))
        for e in c.engagements:
            mark, col = ("●", GREEN) if e.authorized else ("○", AMBER)
            state = "authorized" if e.authorized else "NOT authorized"
            console.print(Text.assemble(
                (f"      {mark} ", f"bold {col}"), (e.name, "white"), (f"  [{e.slug}]", "dim"),
                (f"   {state}", col), (f"   ·  {e.created}" if e.created else "", "dim")))
            if e.roe:
                console.print(Text.assemble(("          RoE  ", f"bold {DIM}"), (e.roe, "dim")))
            if e.scope:
                for s in e.scope:
                    console.print(Text.assemble(("          → ", BLUE), (s, "white")))
            else:
                console.print(Text("          (no targets in scope yet)", style="dim"))


def _pick_client(console: Console, message: str = "Which client?") -> Optional[Client]:
    clients = list_clients()
    if not clients:
        console.print(Text("No clients yet — create one first.", style=AMBER))
        return None
    items = [(c.slug, c.name, f"[{c.slug}]  {len(c.engagements)} engagement(s)") for c in clients]
    slug = _pick(console, message, items)
    return get_client(slug) if slug else None


def _pick_engagement(console: Console, client: Client,
                     message: str = "Which engagement?") -> Optional[Engagement]:
    if not client.engagements:
        console.print(Text("This client has no engagements yet.", style=AMBER))
        return None
    items = []
    for e in client.engagements:
        tag = "authorized" if e.authorized else "not authorized"
        items.append((e.slug, e.name, f"[{e.slug}]  {tag} · {len(e.scope)} target(s)"))
    slug = _pick(console, message, items)
    return get_engagement(client, slug) if slug else None


def _prompt_targets(console: Console) -> List[str]:
    """Read scope targets: several per line (space/comma separated) or one per line; blank = done."""
    console.print(Text.assemble(
        ("Scope targets  ", f"bold {BLUE}"),
        ("— URLs / domains / hosts you're authorized to test. Separate with spaces/commas, "
         "or add one line at a time (blank line = done).", "dim")))
    out: List[str] = []
    while True:
        line = Prompt.ask(f"[{BLUE}]target(s) (blank = done)[/]", default="").strip()
        if not line:
            break
        for tok in re.split(r"[\s,]+", line):
            tok = _clean_target(tok)
            if tok:
                out.append(tok)
    return _dedupe(out)


def _new_client_flow(console: Console) -> None:
    name = Prompt.ask(f"[{BLUE}]Client name[/] [dim](blank = cancel)[/]", default="").strip()
    if not name:
        console.print("[dim]Cancelled.[/]")
        return
    notes = Prompt.ask(f"[{BLUE}]Notes[/] [dim](optional)[/]", default="").strip()
    c = add_client(name, notes=notes)
    console.print(Text.assemble(("✓ created client ", f"bold {GREEN}"),
                                (c.name, "bold white"), (f"  [{c.slug}]", "dim")))
    if Confirm.ask("Add an engagement now?", default=True):
        _new_engagement_flow(console, client=c)


def _new_engagement_flow(console: Console, client: Optional[Client] = None) -> None:
    c = client or _pick_client(console, "Add an engagement to which client?")
    if not c:
        if Confirm.ask("No client selected — create a new client now?", default=True):
            _new_client_flow(console)
        return
    name = Prompt.ask(f"[{BLUE}]Engagement name[/] "
                      f"[dim](e.g. 'Q3 external assessment' — blank = cancel)[/]", default="").strip()
    if not name:
        console.print("[dim]Cancelled.[/]")
        return
    scope = _prompt_targets(console)
    roe = Prompt.ask(f"[{BLUE}]Rules of engagement[/] [dim](note, optional)[/]", default="").strip()
    console.print(Text.assemble(
        ("⚠ ", f"bold {AMBER}"),
        ("Only mark this authorized if you have written permission to test every target above.",
         f"italic {AMBER}")))
    authorized = Confirm.ask(f"[{AMBER}]Is this engagement authorized?[/]", default=False)
    e = add_engagement(c, name, scope=scope, authorized=authorized, roe=roe)
    state = "authorized ✓" if e.authorized else "NOT authorized (targets stay un-pickable)"
    console.print(Text.assemble(
        ("✓ opened engagement ", f"bold {GREEN}"), (e.name, "bold white"), (f"  [{e.slug}]", "dim"),
        (f"  · {len(e.scope)} target(s) · {state}", GREEN if e.authorized else AMBER)))


def _add_target_flow(console: Console) -> None:
    c = _pick_client(console)
    if not c:
        return
    e = _pick_engagement(console, c)
    if not e:
        return
    targets = _prompt_targets(console)
    if not targets:
        console.print("[dim]No targets entered.[/]")
        return
    e2 = add_targets(c, e, targets)
    console.print(Text.assemble(
        ("✓ scope for ", f"bold {GREEN}"), (e2.name, "bold white"),
        (f" now holds {len(e2.scope)} target(s).", "dim")))


def _toggle_auth_flow(console: Console) -> None:
    c = _pick_client(console)
    if not c:
        return
    e = _pick_engagement(console, c)
    if not e:
        return
    if e.authorized:
        if Confirm.ask(f"'{e.name}' is authorized — revoke authorization?", default=False):
            set_authorized(c, e, False)
            console.print(Text("✓ authorization revoked — its targets are no longer pickable.",
                               style=AMBER))
    else:
        console.print(Text.assemble(
            ("⚠ ", f"bold {AMBER}"),
            ("Confirm you have written permission to test every target in this engagement.",
             f"italic {AMBER}")))
        if Confirm.ask(f"[{AMBER}]Mark '{e.name}' authorized?[/]", default=False):
            set_authorized(c, e, True)
            console.print(Text("✓ engagement authorized — its in-scope targets are now pickable.",
                               style=GREEN))

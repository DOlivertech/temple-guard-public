"""temple-guard — scan your own web app and get a remediation report.

Authorized / self-assessment use only. Only scan applications you own or have
explicit written permission to test.
"""
from __future__ import annotations

import importlib.metadata as _ilm
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.text import Text

try:  # optional — gives us the nice block wordmark; degrade gracefully if absent
    from art import text2art
except Exception:  # pragma: no cover
    text2art = None

from . import __version__, tools
from .checks import CHECK_PLAN, SEV_RANK, scan as run_scan
from .report import BLUE, PURPLE, make_progress_reporter, render, to_html, to_markdown, to_pdf

app = typer.Typer(add_completion=False, no_args_is_help=False,
                  help="Scan a web app you own and get a remediation report.")
console = Console()

# --- brand mark: the Temple Guard shield (navy shield · gold mask · saberstaff)
SHIELD = "#38bdf8"   # blue shield outline
SABER = "#ffd60a"    # yellow saberstaff blades
HILT = "#94a3b8"     # steel hilt guards
MASK = "#d9c290"     # gold guard mask
EYE = "#6b5a2a"      # dark eye slits

# each row is a list of (text, colour|None) segments — 11 cells wide, saber on col 5
_EMBLEM = [
    [("  ╭───────────╮  ", SHIELD)],
    [("  │     ", SHIELD), ("┃", SABER), ("     │  ", SHIELD)],
    [("  │    ", SHIELD), ("▟", SABER), ("█", HILT), ("▙", SABER), ("    │  ", SHIELD)],
    [("  │   ", SHIELD), ("▟", MASK), ("█", MASK), ("█", MASK), ("█", MASK), ("▙", MASK), ("   │  ", SHIELD)],
    [("  │   ", SHIELD), ("█", MASK), ("▜", EYE), ("█", HILT), ("▛", EYE), ("█", MASK), ("   │  ", SHIELD)],
    [("  │   ", SHIELD), ("▜", MASK), ("█", MASK), ("█", MASK), ("█", MASK), ("▛", MASK), ("   │  ", SHIELD)],
    [("  │    ", SHIELD), ("▜", SABER), ("█", HILT), ("▛", SABER), ("    │  ", SHIELD)],
    [("  ╰╮    ", SHIELD), ("┃", SABER), ("    ╭╯  ", SHIELD)],
    [("   ╰╮   ", SHIELD), ("┃", SABER), ("   ╭╯   ", SHIELD)],
    [("    ╰───", SHIELD), ("┸", SABER), ("───╯    ", SHIELD)],
]
_EMBLEM_W = 17


def _hex(c: str) -> tuple[int, int, int]:
    c = c.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def _mix(a: str, b: str, t: float) -> str:
    ar, ag, ab = _hex(a)
    br, bg, bb = _hex(b)
    return f"#{round(ar+(br-ar)*t):02x}{round(ag+(bg-ag)*t):02x}{round(ab+(bb-ab)*t):02x}"


def _emblem_row(row, indent: int) -> Text:
    t = Text(" " * indent)
    for seg, style in row:
        t.append(seg, style=f"bold {style}" if style else None)
    return t


def _wordmark_lines() -> tuple[list[str], int]:
    if text2art is not None:
        try:
            lines = text2art("TEMPLE GUARD", font="small").rstrip("\n").split("\n")
        except Exception:  # pragma: no cover
            lines = ["TEMPLE GUARD"]
    else:
        lines = ["TEMPLE GUARD"]
    width = max((len(ln) for ln in lines), default=12)
    return [ln.ljust(width) for ln in lines], width


def _banner(animate: bool) -> None:
    words, word_w = _wordmark_lines()
    indent = max((word_w - _EMBLEM_W) // 2, 0)  # centre the shield over the wordmark
    anim = animate and console.is_terminal

    # 1) the shield emblem, revealed row by row
    for row in _EMBLEM:
        console.print(_emblem_row(row, indent))
        if anim:
            sys.stdout.flush()
            time.sleep(0.03)
    console.print()

    # 2) "TEMPLE GUARD" wordmark with a purple→blue gradient sweep
    span = max(word_w - 1, 1)
    for ln in words:
        if anim:
            for i, ch in enumerate(ln):
                console.print(Text(ch, style=f"bold {_mix(PURPLE, BLUE, min(i, span) / span)}"), end="")
                sys.stdout.flush()
                time.sleep(0.0018)
            console.print()
        else:
            t = Text()
            for i, ch in enumerate(ln):
                t.append(ch, style=f"bold {_mix(PURPLE, BLUE, min(i, span) / span)}")
            console.print(t)

    # 3) tagline
    console.print(Text.assemble(("  self-assessment scanner", f"dim {BLUE}"),
                                (f"   ·   v{__version__}", "dim")))
    console.print()


def _authz_notice() -> None:
    console.print(Text.assemble(
        ("⚠ ", "bold #fbbf24"),
        ("Authorized use only — scan apps you OWN or have written permission to test.",
         "italic #fbbf24")))


def _pick(message: str, items: list, default: str = None):
    """Fuzzy, type-to-filter selector (fzy / fzf-style). `items` = [(value, label, desc)].
    Returns the chosen value, or None if cancelled. Falls back to a numbered rich prompt
    when a fuzzy TTY isn't available (or TG_NO_FUZZY is set)."""
    if sys.stdin.isatty() and console.is_terminal and not os.environ.get("TG_NO_FUZZY"):
        try:
            from InquirerPy import inquirer
            from InquirerPy.base.control import Choice
            choices = [Choice(value=v, name=(f"{lbl}   ·   {d}" if d else lbl)) for v, lbl, d in items]
            return inquirer.fuzzy(
                message=message, choices=choices, border=True,
                max_height="70%", cycle=True, pointer="❯", qmark="›", amark="›",
                instruction="(type to filter · ↑↓ move · enter select · esc cancel)",
            ).execute()
        except KeyboardInterrupt:
            return None
        except Exception:  # any TTY / import issue → graceful fallback
            pass
    console.print(Text(f"\n{message}", style=f"bold {PURPLE}"))
    for v, lbl, d in items:
        console.print(Text.assemble((f"  {v}  ", f"bold {BLUE}"), (lbl.ljust(16), "bold white"), (d, "dim")))
    keys = [v for v, _, _ in items]
    return Prompt.ask(f"[{BLUE}]Choose[/]", choices=keys, default=default or keys[0])


def _dry_cmd(label: str, cmd: list) -> None:
    """Show the exact command an action WOULD run, and run nothing."""
    console.print(Text.assemble((" DRY RUN ", "bold #fbbf24 reverse"), ("  ", ""), (label, "bold white")))
    console.print(Text.assemble(("  $ ", f"bold {BLUE}"), (" ".join(cmd), "#e2e8f0")))
    console.print(Text("  ↑ nothing was run — this is what would execute.", style="dim italic"))


def _print_dry_run(url: str) -> None:
    console.print(Text("DRY RUN", style=f"bold {PURPLE} reverse"),
                  Text(f" — would run these read-only checks against {url}:", style="dim"))
    for cat, name, desc in CHECK_PLAN:
        console.print(Text.assemble(("  • ", f"{BLUE}"), (f"{name}", "bold white"),
                                    (f"  {desc}", "dim")))
    console.print(Text("\nNo requests were sent.", style="dim italic"))


def _result_dict(result) -> dict:
    return {
        "url": result.url, "reachable": result.reachable, "status": result.status,
        "server": result.server, "error": result.error,
        "findings": [f.__dict__ for f in result.findings],
    }


def _run(url: str, verbose: bool):
    """Run the scan behind an animated progress bar. Verbose streams each check and
    finding above the bar as it goes; either way the bar fills as checks complete."""
    from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                               TimeElapsedColumn)
    total = len(CHECK_PLAN)
    with Progress(
        SpinnerColumn(style=PURPLE),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=None, style="#334155", complete_style=BLUE, finished_style="#4ade80"),
        TextColumn("[dim]{task.completed}/{task.total}[/]"),
        TimeElapsedColumn(),
        console=console, transient=True,
    ) as progress:
        task = progress.add_task(f"scanning {url}", total=total)
        printer = make_progress_reporter(progress.console) if verbose else None

        def on_event(kind: str, **k) -> None:
            if kind == "step":
                progress.update(task, description=k.get("name", "scanning…"))
                progress.advance(task)
            if printer is not None:
                printer(kind, **k)

        result = run_scan(url, on_event=on_event)
        progress.update(task, completed=total, description="scan complete")
    return result


def _resolve_tools(deep: bool, with_tools) -> list:
    """Resolve which Docker tools to run: --deep = all defensive, --tools = a list."""
    if with_tools:
        wanted = [t.strip() for t in str(with_tools).replace(",", " ").split() if t.strip()]
        return [n for n in wanted if n in tools.TOOLS]
    return list(tools.DEFENSIVE) if deep else []


def _run_tools(url: str, names: list, verbose: bool, quiet: bool = False) -> list:
    """Run the selected Docker tools (each spins up its image), returning findings."""
    ok, why = tools.docker_available()
    if not ok:
        if not quiet:
            console.print(Text.assemble(("⚠ Docker unavailable — skipping Kali tools: ",
                                         "bold #fbbf24"), (why, "dim")))
        return []
    if quiet:
        out = []
        for name in names:
            fs, _raw, _ok = tools.run_tool(name, url)
            out.extend(fs)
        return out

    from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                               TimeElapsedColumn)
    findings = []
    with Progress(
        SpinnerColumn(style=PURPLE),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=None, style="#334155", complete_style=BLUE, finished_style="#4ade80"),
        TextColumn("[dim]{task.completed}/{task.total}[/]"),
        TimeElapsedColumn(),
        console=console, transient=True,
    ) as progress:
        task = progress.add_task("kali tools", total=len(names))
        for name in names:
            tool = tools.TOOLS[name]
            progress.update(task, description=f"{tool.name} — pulling / running")
            fs, raw, okr = tools.run_tool(name, url)
            findings.extend(fs)
            if verbose:
                notable = sum(1 for f in fs if f.severity in ("high", "medium"))
                progress.console.print(Text.assemble(
                    (f"  ⚙ {tool.name}: ", f"bold {BLUE}"),
                    (f"{len(fs)} finding(s)" + (f", {notable} notable" if notable else ""), "white")))
            progress.advance(task)
    return findings


def _write_report(result, path: Path) -> None:
    ext = path.suffix.lower()
    if ext == ".pdf":
        to_pdf(result, str(path))
        kind = "PDF"
    elif ext in (".html", ".htm"):
        path.write_text(to_html(result))
        kind = "HTML"
    elif ext == ".json":
        path.write_text(json.dumps(_result_dict(result), indent=2))
        kind = "JSON"
    else:
        path.write_text(to_markdown(result))
        kind = "markdown"
    console.print(Text.assemble((f"\n✓ {kind} report written to ", f"{BLUE}"), (str(path), "bold white")))


@app.command()
def scan(
    url: str = typer.Argument(..., help="URL of the app to scan (your own / authorized)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would run; make no requests."),
    report: Path = typer.Option(None, "--report", "-o",
                                help="Write a report; format follows the extension (.html/.pdf/.md/.json)."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show each check + finding live as it runs."),
    deep: bool = typer.Option(False, "--deep", help="Also run the Docker recon tools (whatweb, wafw00f, testssl, nmap, nuclei)."),
    with_tools: str = typer.Option(None, "--tools", "-t",
                                   help="Comma-list of Docker tools to also run: whatweb,wafw00f,testssl,nmap,nuclei,nikto."),
    json_out: bool = typer.Option(False, "--json", help="Emit findings as JSON (no styling)."),
    no_anim: bool = typer.Option(False, "--no-anim", help="Disable the banner animation."),
):
    """Run bounded, read-only defensive checks against URL (+ optional Docker tools)."""
    tool_names = _resolve_tools(deep, with_tools)
    if not json_out:
        _banner(animate=not no_anim and not dry_run)
        _authz_notice()
        console.print()

    if dry_run:
        _print_dry_run(url)
        if tool_names:
            console.print(Text("\nWould also run these Docker tools (no containers started):", style="dim"))
            for name in tool_names:
                _dry_cmd(tools.TOOLS[name].name, tools.tool_cmd(name, url))
        raise typer.Exit()

    result = _run(url, verbose=verbose and not json_out)
    if tool_names:
        result.findings.extend(_run_tools(url, tool_names, verbose=verbose and not json_out, quiet=json_out))
        result.findings.sort(key=lambda f: SEV_RANK.get(f.severity, 9))

    if json_out:
        print(json.dumps(_result_dict(result), indent=2))
        raise typer.Exit(code=1 if result.by_severity.get("high") else 0)

    render(result, console)
    if report:
        _write_report(result, report)
    # exit non-zero if any HIGH finding (handy for CI)
    raise typer.Exit(code=1 if result.by_severity.get("high") else 0)


@app.command()
def shell(image: str = typer.Option(None, "--image", help="Container image (default: kalilinux/kali-rolling)."),
          dry_run: bool = typer.Option(False, "--dry-run", help="Show the container command that would run; start nothing.")):
    """Drop into an interactive Kali shell in a container (Docker required)."""
    if dry_run:
        _dry_cmd("Kali shell", tools.shell_cmd(image))
        raise typer.Exit(0)
    ok, why = tools.docker_available()
    if not ok:
        console.print(Text.assemble(("✗ Docker unavailable: ", "bold #f87171"), (why, "dim")))
        raise typer.Exit(code=1)
    console.print(Text.assemble(("Starting a Kali shell in ", "dim"),
                                (image or tools.KALI_SHELL_IMAGE, f"bold {BLUE}"),
                                (" — first run pulls the image (~1 GB). Type 'exit' to leave.", "dim")))
    _authz_notice()
    raise typer.Exit(code=tools.kali_shell(image))


def _describe_tool(key: str, brief: bool = False) -> None:
    """Show an explainer for one tool. Full = what/how/risks/flags (the CLI reference);
    brief = just what + risk (the interactive flow, which then asks guided questions)."""
    from rich.panel import Panel
    t = tools.TOOLS[key]
    body = Text()
    body.append("What   ", style=f"bold {BLUE}")
    body.append(t.what, style="white")
    if not brief:
        body.append("\n\nUse", style=f"bold {BLUE}")
        for ex in t.usage.split("\n"):
            body.append("\n  $ ", style="dim")
            body.append(ex, style="#e2e8f0")
    body.append("\n\nRisk   ", style="bold #fbbf24")
    body.append(t.risk, style="#fcd34d")
    if not brief:
        body.append("\n\nFlags  ", style=f"bold {PURPLE}")
        body.append(t.flags, style="dim")
    console.print(Panel(
        body, padding=(1, 2), border_style=BLUE, title_align="left",
        title=Text.assemble((f" {t.name} ", "bold white"), (f"  [{t.image}]", "dim")),
        subtitle=Text(" read-only container · authorized targets only ", style="dim")))


def _print_tool_usage() -> None:
    console.print(Text("\nRun a Kali tool in its own container with YOUR arguments:",
                       style=f"bold {PURPLE}"))
    console.print(Text.assemble(("  temple-guard tool ", f"bold {BLUE}"), ("<tool> [args…]", "dim")))
    console.print(Text("\nTools (each spins up + runs its own image):", style="dim"))
    for key, t in tools.TOOLS.items():
        console.print(Text.assemble((f"  {key.ljust(9)}", f"bold {BLUE}"), (t.desc, "white")))
    console.print(Text.assemble(
        ("\n  temple-guard tool ", f"bold {BLUE}"), ("<tool>", "bold white"),
        ("   (no args)  →  full explainer: what it is · how to use it · risks · flags", "dim")))
    console.print(Text("\nExamples (full tool flags are passed straight through):", style="dim"))
    for ex in ("temple-guard tool nmap -h                                  # nmap's own full help",
               "temple-guard tool nmap -sV -p 1-1000 host.docker.internal",
               "temple-guard tool nikto -h http://host.docker.internal:8081",
               "temple-guard tool wafw00f https://example.com",
               "temple-guard tool whatweb https://example.com",
               "temple-guard tool testssl --severity LOW example.com",
               "temple-guard tool nuclei -u https://example.com -tags cve,exposure"):
        console.print(Text.assemble(("  ", ""), (ex, "white")))
    console.print(Text("\nUse host.docker.internal for an app on your own machine "
                       "(localhost is auto-remapped). Authorized targets only.", style="dim"))


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
             add_help_option=False)
def tool(ctx: typer.Context,
         name: str = typer.Argument(None, help="testssl | nmap | nuclei | nikto | wafw00f | whatweb")):
    """Run a Kali tool in its container with YOUR arguments — the tool's full flag set.

    Examples:
      temple-guard tool nmap -sV -p 1-1000 host.docker.internal
      temple-guard tool nmap -h                 (nmap's own help)
      temple-guard tool wafw00f https://example.com
      temple-guard tool nuclei -u https://example.com -tags cve
    """
    if not name or name in ("-h", "--help") or name not in tools.TOOLS:
        _print_tool_usage()
        raise typer.Exit(0 if name in (None, "-h", "--help") else 1)
    args = list(ctx.args)
    dry = False
    for flag in ("--dry-run", "--tg-dry-run"):
        if flag in args:
            dry, args = True, [a for a in args if a != flag]
    if not args:
        # a bare `tool <name>` is a request to learn about it — show the explainer
        _describe_tool(name)
        console.print(f"[dim]Add arguments to run it — copy one of the examples above "
                      f"(or `temple-guard tool {name} -h` for the tool's own help).[/]")
        raise typer.Exit(0)
    if dry:
        _dry_cmd(f"{name} {' '.join(args)}", tools.raw_cmd(name, args))
        raise typer.Exit(0)
    ok, why = tools.docker_available()
    if not ok:
        console.print(Text.assemble(("✗ Docker unavailable: ", "bold #f87171"), (why, "dim")))
        raise typer.Exit(1)
    _authz_notice()
    console.print(Text.assemble((f"⚙ {name} ", f"bold {PURPLE}"), (" ".join(args), "dim"),
                                (f"   [{tools.TOOLS[name].image}]", "dim")))
    with console.status(f"[{PURPLE}]running {name}…", spinner="dots"):
        rc, out = tools.run_raw(name, args)
    print(out or "(no output)")
    raise typer.Exit(rc)


# ── self-update: pull the newest temple-guard from its git repo ─────────────
DEFAULT_UPDATE_REPO = "https://github.com/DOlivertech/temple-guard-public.git"
_MANAGED_CHECKOUT = Path.home() / ".local" / "share" / "temple-guard" / "repo"


def _run_cmd(cmd: list, cwd=None, timeout: int = 600) -> tuple:
    # GIT_TERMINAL_PROMPT=0 so a private/auth'd remote fails fast instead of hanging on a prompt
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except FileNotFoundError as exc:
        return 127, str(exc)
    except Exception as exc:  # noqa: BLE001
        return 1, str(exc)


def _pkg_source_checkout():
    """If temple-guard is running from a git checkout, return its repo root (else None)."""
    try:
        here = Path(__file__).resolve()
    except Exception:  # pragma: no cover
        return None
    for parent in here.parents:
        if (parent / ".git").exists():
            return parent
    return None


def _is_editable_install() -> bool:
    try:
        durl = _ilm.distribution("temple-guard").read_text("direct_url.json")
        return bool(durl and json.loads(durl).get("dir_info", {}).get("editable"))
    except Exception:  # noqa: BLE001
        return False


def _src_version(cli_dir: Path):
    try:
        text = (cli_dir / "temple_guard" / "__init__.py").read_text()
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', text)
        return m.group(1) if m else None
    except Exception:  # noqa: BLE001
        return None


def _reinstall_cmd(cli_dir: Path) -> list:
    editable = _is_editable_install()
    if shutil.which("pipx"):
        return ["pipx", "install", "--force"] + (["--editable"] if editable else []) + [str(cli_dir)]
    return ([sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall"]
            + (["-e"] if editable else []) + [str(cli_dir)])


def _do_update(check: bool = False, repo: str = DEFAULT_UPDATE_REPO, ref: str = "main") -> int:
    """Source the repo and reinstall. Returns an exit code."""
    console.print(Text.assemble(("temple-guard ", f"bold {PURPLE}"), (f"v{__version__}", "white"),
                                ("  ·  checking for updates…", "dim")))
    if not shutil.which("git"):
        console.print("[#f87171]✗ git not found — install git to self-update "
                      "(or grab a build from the Releases page).[/]")
        return 1

    checkout = _pkg_source_checkout()
    if checkout:
        cli_dir = (checkout / "cli") if (checkout / "cli").exists() else checkout
        console.print(Text.assemble(("  source  ", "dim"), (str(checkout), f"{BLUE}"), ("  (local checkout)", "dim")))
        rc, out = _run_cmd(["git", "pull", "--ff-only"], cwd=str(checkout))
        last = out.splitlines()[-1] if out else ""
        if rc != 0:
            console.print(Text.assemble(("  ⚠ git pull skipped: ", "bold #fbbf24"), (last[:160] or "no upstream", "dim")))
            console.print("[dim]  Reinstalling from the current local source instead.[/]")
        else:
            console.print(f"[dim]  {last or 'already up to date'}[/]")
    else:
        cli_dir = _MANAGED_CHECKOUT / "cli"
        console.print(Text.assemble(("  source  ", "dim"), (repo, f"{BLUE}"), (f"  ({ref})", "dim")))
        if (_MANAGED_CHECKOUT / ".git").exists():
            rc, out = _run_cmd(["git", "fetch", "origin", ref], cwd=str(_MANAGED_CHECKOUT))
            if rc == 0:
                rc, out = _run_cmd(["git", "reset", "--hard", f"origin/{ref}"], cwd=str(_MANAGED_CHECKOUT))
        else:
            _MANAGED_CHECKOUT.parent.mkdir(parents=True, exist_ok=True)
            rc, out = _run_cmd(["git", "clone", "--depth", "1", "--branch", ref, repo, str(_MANAGED_CHECKOUT)])
        if rc != 0:
            console.print(Text.assemble(("  ✗ could not fetch the repo: ", "bold #f87171"), (out[:300], "dim")))
            console.print("[dim]  If the repo is private, clone it yourself and run "
                          "`pipx install --force ./cli` from inside it.[/]")
            return 1

    target = _src_version(cli_dir) or "?"
    if target != "?" and target == __version__:
        console.print(Text.assemble(("  ✓ already on the latest version ", "bold #4ade80"), (f"(v{__version__}).", "dim")))
        return 0

    console.print(Text.assemble(("  update  ", "dim"), (f"v{__version__} → v{target}", "bold white")))
    if check:
        console.print("[dim]  --check only; nothing installed. Run `temple-guard update` to apply.[/]")
        return 0

    cmd = _reinstall_cmd(cli_dir)
    console.print(Text.assemble(("  installing  ", "dim"), (" ".join(cmd[:2]) + " …", f"{BLUE}")))
    with console.status(f"[{PURPLE}]reinstalling temple-guard…", spinner="dots"):
        rc, out = _run_cmd(cmd)
    if rc != 0:
        console.print(Text.assemble(("  ✗ reinstall failed: ", "bold #f87171"), (out[-400:], "dim")))
        return 1
    console.print(Text.assemble(("\n✓ updated to ", "bold #4ade80"), (f"temple-guard v{target}", "bold white")))
    console.print("[dim]  Open a new shell (or re-run) to pick it up — confirm with `temple-guard version`.[/]")
    return 0


@app.command()
def update(
    check: bool = typer.Option(False, "--check", help="Only report whether a newer version exists; install nothing."),
    repo: str = typer.Option(DEFAULT_UPDATE_REPO, "--repo", help="Git repo to pull from if not run from a checkout."),
    ref: str = typer.Option("main", "--ref", help="Branch or tag to update to."),
):
    """Update temple-guard to the newest version from its git repo (source → reinstall)."""
    raise typer.Exit(_do_update(check=check, repo=repo, ref=ref))


_COMMANDS = [
    ("temple-guard", "this interactive menu"),
    ("temple-guard scan <url>", "native read-only checks + report"),
    ("temple-guard scan <url> -v", "verbose — each check + finding, live"),
    ("temple-guard scan <url> --deep", "add the Docker recon tools (whatweb, wafw00f, testssl, nmap, nuclei)"),
    ("temple-guard scan <url> --tools nmap,nikto", "run specific Docker tools"),
    ("temple-guard scan <url> --dry-run", "list the checks, send nothing"),
    ("temple-guard scan <url> -o report.html", "save a report (.html / .pdf / .md / .json)"),
    ("temple-guard tool", "list the Docker tools"),
    ("temple-guard tool <name>", "full explainer for a tool (what · how · risks · flags)"),
    ("temple-guard tool nmap <args>", "run a Kali tool with your own flags (full arg set)"),
    ("temple-guard tool nmap --dry-run", "preview the docker command for a tool; run nothing"),
    ("temple-guard tool nmap -h", "the tool's own help / full options"),
    ("temple-guard shell", "interactive Kali shell in a container"),
    ("temple-guard shell --dry-run", "preview the shell container command; start nothing"),
    ("temple-guard update", "update to the newest version from the repo"),
    ("temple-guard update --check", "check for a newer version, install nothing"),
    ("temple-guard version", "print the version"),
    ("temple-guard --help", "full command reference"),
]


def _print_checks() -> None:
    console.print(Text("\nWhat temple-guard checks (all bounded & read-only):", style=f"bold {PURPLE}"))
    for cat, name, desc in CHECK_PLAN:
        console.print(Text.assemble(("  • ", f"{BLUE}"), (name, "bold white"), (f"   {desc}", "dim")))


def _print_commands() -> None:
    console.print(Text("\nCommands:", style=f"bold {PURPLE}"))
    for cmd, desc in _COMMANDS:
        console.print(Text.assemble(("  ", ""), (cmd.ljust(42), f"{BLUE}"), (desc, "dim")))


def _scan_flow(deep: bool = False, dry: bool = False) -> None:
    """Prompt for a target + options, run the scan (+ Docker tools if deep), offer to save.
    In dry mode: print the checks + tool commands that would run, and run nothing."""
    url = Prompt.ask(f"[{BLUE}]Target URL[/] "
                     f"[dim](e.g. https://beta.example.com — blank to cancel)[/]").strip()
    if not url:
        console.print("[dim]No target — back to the menu.[/]")
        return
    if " " in url:
        console.print("[#f87171]A target is a single URL — no spaces.[/]")
        return
    url = _norm_target(url, "url")
    if dry:
        console.print()
        _print_dry_run(url)
        if deep:
            console.print(Text("\nWould also run these Docker tools (no containers started):", style="dim"))
            for name in tools.DEFENSIVE:
                _dry_cmd(tools.TOOLS[name].name, tools.tool_cmd(name, url))
        return
    if not Confirm.ask("[#fbbf24]I'm authorized to test this target. Run the scan?[/]", default=True):
        console.print("[dim]Cancelled — nothing was sent.[/]")
        return
    verbose = Confirm.ask("Verbose live output?", default=True)
    console.print()
    result = _run(url, verbose=verbose)
    if deep:
        result.findings.extend(_run_tools(url, list(tools.DEFENSIVE), verbose=verbose))
        result.findings.sort(key=lambda f: SEV_RANK.get(f.severity, 9))
    render(result, console)
    fmt = Prompt.ask("Save a report?", choices=["no", "html", "markdown", "pdf", "json"], default="no")
    if fmt != "no":
        ext = {"html": "html", "markdown": "md", "pdf": "pdf", "json": "json"}[fmt]
        path = Path(Prompt.ask("File path", default=f"temple-guard-report.{ext}"))
        _write_report(result, path)


def _shell_flow(dry: bool = False) -> None:
    if dry:
        _dry_cmd("Kali shell", tools.shell_cmd())
        return
    ok, why = tools.docker_available()
    if not ok:
        console.print(Text.assemble(("✗ Docker unavailable: ", "bold #f87171"), (why, "dim")))
        return
    console.print(Text.assemble(("Starting a Kali shell (", "dim"),
                                (tools.KALI_SHELL_IMAGE, f"bold {BLUE}"),
                                (") — first run pulls the image. Type 'exit' to return.", "dim")))
    tools.kali_shell()


# Guided prompts for the interactive "Run a tool" flow: the common options become
# questions (choices / yes-no) instead of raw flags, and the command is assembled for you.
# Each step is either a "choices" list of (label, argv-tokens) or a yes/no "flag".
TOOL_GUIDE = {
    "whatweb": {
        "base": ["--color=never"],
        "target": {"prompt": "Target URL", "eg": "https://beta.example.com", "kind": "url", "arg": ["{}"]},
        "steps": [
            {"ask": "Aggression", "choices": [
                ("passive — default", []), ("more requests (-a 3)", ["-a", "3"]), ("heavy (-a 4)", ["-a", "4"])]},
            {"ask": "Verbose output?", "flag": ["-v"], "default": False},
        ],
    },
    "wafw00f": {
        "base": [],
        "target": {"prompt": "Target URL", "eg": "https://beta.example.com", "kind": "url", "arg": ["{}"]},
        "steps": [
            {"ask": "Test every WAF signature (slower, thorough)?", "flag": ["-a"], "default": False},
            {"ask": "Verbose output?", "flag": ["-v"], "default": False},
        ],
    },
    "nmap": {
        "base": ["-Pn"],
        "target": {"prompt": "Target host", "eg": "beta.example.com or localhost", "kind": "host", "arg": ["{}"]},
        "steps": [
            {"ask": "Detection", "choices": [
                ("service + version (-sV)", ["-sV"]), ("aggressive: OS + default scripts (-A)", ["-A"])]},
            {"ask": "Ports", "choices": [
                ("top 200 — default", ["--top-ports", "200"]), ("top 1000", ["--top-ports", "1000"]),
                ("range 1-1000", ["-p", "1-1000"]), ("all 65535 (slow)", ["-p-"])]},
            {"ask": "Faster timing (-T4)?", "flag": ["-T4"], "default": True},
        ],
    },
    "testssl": {
        "base": ["--quiet", "--color", "0"],
        "target": {"prompt": "Target host[:port]", "eg": "beta.example.com or beta.example.com:443",
                   "kind": "hostport", "arg": ["{}"]},
        "steps": [
            {"ask": "Scope", "choices": [
                ("full posture — default", []), ("protocols only (-p)", ["-p"]), ("vulnerabilities only (-U)", ["-U"])]},
            {"ask": "Minimum severity to report", "choices": [
                ("all — default", []), ("LOW and up", ["--severity", "LOW"]),
                ("MEDIUM and up", ["--severity", "MEDIUM"]), ("HIGH and up", ["--severity", "HIGH"])]},
        ],
    },
    "nuclei": {
        "base": ["-silent"],
        "target": {"prompt": "Target URL", "eg": "https://beta.example.com", "kind": "url", "arg": ["-u", "{}"]},
        "steps": [
            {"ask": "Severity", "choices": [
                ("low → critical — default", ["-severity", "low,medium,high,critical"]),
                ("high + critical only", ["-severity", "high,critical"]), ("all severities", [])]},
            {"ask": "Templates", "choices": [
                ("misconfig + exposure — default", ["-tags", "misconfig,exposure,tech"]),
                ("known CVEs", ["-tags", "cve"]), ("everything", [])]},
        ],
    },
    "nikto": {
        "base": ["-ask", "no"],
        "target": {"prompt": "Target URL", "eg": "https://beta.example.com or http://localhost:8081",
                   "kind": "url", "arg": ["-h", "{}"]},
        "steps": [
            {"ask": "Max scan time", "choices": [
                ("3 min — default", ["-maxtime", "180"]), ("1 min (quick)", ["-maxtime", "60"]), ("no limit", [])]},
            {"ask": "Force SSL/TLS (-ssl)?", "flag": ["-ssl"], "default": False},
        ],
    },
}


def _ask_choice(prompt: str, choices: list):
    """Numbered pick from (label, tokens) pairs; default is the first. Returns the tokens."""
    console.print(Text(f"\n{prompt}", style=f"bold {BLUE}"))
    for i, (label, _tokens) in enumerate(choices, 1):
        console.print(Text.assemble((f"  {i}  ", f"bold {BLUE}"), (label, "white")))
    idx = Prompt.ask("Pick", choices=[str(i) for i in range(1, len(choices) + 1)], default="1")
    return choices[int(idx) - 1][1]


def _norm_target(val: str, kind: str) -> str:
    """Tidy a typed target: add a scheme for URL tools; strip scheme/path (and port) for host tools."""
    val = val.strip().rstrip("/")
    if kind == "url":
        if "://" in val:
            return val
        host = val.split("/", 1)[0]
        # bare domain → https; localhost or a host:port → http (don't mangle local dev apps)
        local = host.split(":", 1)[0] in ("localhost", "127.0.0.1", "0.0.0.0") or ":" in host
        return ("http://" if local else "https://") + val
    if "://" in val:
        val = val.split("://", 1)[1]
    val = val.split("/", 1)[0]              # drop any path
    if kind == "host":
        val = val.split(":", 1)[0]          # nmap wants a bare host (ports go via -p)
    return val


def _ask_target(tgt: dict):
    """Prompt for a target with a format example + light validation. Returns the tidied
    value, or None to cancel. Rejects empty / multi-token input (the classic 'your own' trap)."""
    kind = tgt.get("kind", "url")
    for _ in range(3):
        raw = Prompt.ask(f"[{BLUE}]{tgt['prompt']}[/] "
                         f"[dim](e.g. {tgt.get('eg', 'example.com')} — blank to cancel)[/]").strip()
        if not raw:
            return None
        if " " in raw or "," in raw:
            console.print("[#f87171]  A target is a single host / URL — no spaces or commas. "
                          "Try again.[/]")
            continue
        return _norm_target(raw, kind)
    return None


def _guided_tool_args(name: str):
    """Ask the tool's guided questions and assemble its argv. Returns the list, or None if cancelled."""
    guide = TOOL_GUIDE.get(name)
    if not guide:  # fallback for any tool without a guide — free-form flags
        s = Prompt.ask(f"[{BLUE}]{name} args[/] [dim](blank to cancel)[/]", default="").strip()
        return s.split() if s else None
    tgt = guide["target"]
    val = _ask_target(tgt)
    if not val:
        return None
    argv = list(guide.get("base", []))
    for step in guide["steps"]:
        if "choices" in step:
            argv += _ask_choice(step["ask"], step["choices"])
        elif Confirm.ask(step["ask"], default=step.get("default", False)):
            argv += step["flag"]
    extra = Prompt.ask("[dim]Extra flags (optional — blank for none)[/]", default="").strip()
    if extra:
        argv += extra.split()
    return argv + [t.replace("{}", val) for t in tgt["arg"]]


def _tool_flow(dry: bool = False) -> None:
    if not dry:
        ok, why = tools.docker_available()
        if not ok:
            console.print(Text.assemble(("✗ Docker unavailable: ", "bold #f87171"), (why, "dim")))
            return
    name = _pick("Which tool?", [(k, t.name, t.desc) for k, t in tools.TOOLS.items()], default="nmap")
    if not name:
        console.print("[dim]No tool selected — back to the menu.[/]")
        return
    _describe_tool(name, brief=True)
    console.print("[dim]Answer a few questions — temple-guard builds the command for you "
                  "(or use [/]" + f"[{BLUE}]temple-guard tool {name} <flags>[/]" + "[dim] for raw flags).[/]")
    argv = _guided_tool_args(name)
    if not argv:
        console.print("[dim]Cancelled — back to the menu.[/]")
        return
    console.print(Text.assemble(("\nCommand  ", "dim"),
                                (f"temple-guard tool {name} " + " ".join(argv), f"bold {BLUE}")))
    if dry:
        _dry_cmd(f"{name} {' '.join(argv)}", tools.raw_cmd(name, argv))
        return
    _authz_notice()
    if not Confirm.ask("[#fbbf24]Run this?[/]", default=True):
        console.print("[dim]Cancelled — back to the menu.[/]")
        return
    with console.status(f"[{PURPLE}]running {name}…", spinner="dots"):
        rc, out = tools.run_raw(name, argv)
    print(out or "(no output)")


@app.command()
def interactive() -> None:
    """Interactive, colourful menu — fuzzy-pick what to run (type to filter)."""
    _banner(animate=True)
    _authz_notice()
    dry = False

    while True:
        if dry:
            console.print(Text.assemble(
                ("\n ● DRY-RUN ", "bold #fbbf24 reverse"),
                ("  every action is previewed — nothing is sent or run.", "italic #fbbf24")))
        items = [
            ("1", "Scan a target", "read-only native checks"),
            ("2", "Deep scan", "native checks + Docker recon tools"),
            ("3", "Run a tool", "one Kali tool with your own arguments"),
            ("4", "Kali shell", "interactive shell in a Kali container"),
            ("5", "What it checks", "list the checks temple-guard runs"),
            ("6", "Help", "commands & flags"),
            ("7", "Update", "pull the newest temple-guard from its repo"),
            ("d", f"Dry-run: {'ON' if dry else 'OFF'}", "toggle preview-only mode for every action"),
            ("q", "Quit", ""),
        ]
        choice = _pick("What would you like to do?", items, default="1")

        if choice in (None, "q"):
            console.print("[dim]Bye — stay safe out there.[/]")
            raise typer.Exit()
        if choice == "d":
            dry = not dry
            continue
        console.print()
        if choice == "1":
            _scan_flow(deep=False, dry=dry)
        elif choice == "2":
            _scan_flow(deep=True, dry=dry)
        elif choice == "3":
            _tool_flow(dry=dry)
        elif choice == "4":
            _shell_flow(dry=dry)
        elif choice == "5":
            _print_checks()
        elif choice == "6":
            _print_commands()
        elif choice == "7":
            _do_update(check=True) if dry else _do_update()


@app.command()
def version():
    """Print the temple-guard version."""
    console.print(f"temple-guard {__version__}")


@app.callback(invoke_without_command=True)
def _default(ctx: typer.Context) -> None:
    """Run bare `temple-guard` (no command) → the interactive session."""
    if ctx.invoked_subcommand is None:
        interactive()


if __name__ == "__main__":
    app()

"""temple-guard — scan your own web app and get a remediation report.

Authorized / self-assessment use only. Only scan applications you own or have
explicit written permission to test.
"""
from __future__ import annotations

import contextlib
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
from .report import BLUE, PURPLE, SEV_STYLE, make_progress_reporter, render, to_html, to_markdown, to_pdf

app = typer.Typer(add_completion=False, no_args_is_help=False,
                  help="Scan a web app you own and get a remediation report.")
console = Console()

# --- brand mark: the Temple Guard shield (blue shield · gold mask · a lightsaber blade in front)
SHIELD = "#38bdf8"   # blue shield outline
SABER = "#ffd60a"    # gold lightsaber blade
HILT = "#94a3b8"     # steel hilt
MASK = "#d9c290"     # gold guard mask
EYE = "#6b5a2a"      # dark eye slits
TIP = "#fff7cc"      # bright glowing blade tip

# each row is a list of (text, colour|None) segments — 11 cells wide, a thick gold blade IN FRONT
# on the centre column (bright tip up top, steel hilt below), drawn over the guard mask.
_EMBLEM = [
    [("  ╭───────────╮  ", SHIELD)],
    [("  │     ", SHIELD), ("█", TIP), ("     │  ", SHIELD)],
    [("  │     ", SHIELD), ("█", SABER), ("     │  ", SHIELD)],
    [("  │   ", SHIELD), ("▟█", MASK), ("█", SABER), ("█▙", MASK), ("   │  ", SHIELD)],
    [("  │   ", SHIELD), ("█", MASK), ("▜", EYE), ("█", SABER), ("▛", EYE), ("█", MASK), ("   │  ", SHIELD)],
    [("  │   ", SHIELD), ("▜█", MASK), ("█", SABER), ("█▛", MASK), ("   │  ", SHIELD)],
    [("  │    ", SHIELD), ("▟", HILT), ("█", SABER), ("▙", HILT), ("    │  ", SHIELD)],
    [("  │    ", SHIELD), ("▐█▌", HILT), ("    │  ", SHIELD)],
    [("   ╰╮   ", SHIELD), ("█", HILT), ("   ╭╯   ", SHIELD)],
    [("    ╰───", SHIELD), ("┸", HILT), ("───╯    ", SHIELD)],
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


# Colours for the fuzzy menu (InquirerPy renders each row as one style, so colour lives in
# the pointer / current row / match highlight; the numbered fallback below is fully Rich-coloured).
_MENU_STYLE = {
    "questionmark": "#a78bfa bold",
    "answermark": "#a78bfa",
    "answer": "#38bdf8 bold",
    "pointer": "#ffd60a bold",
    "marker": "#4ade80",
    "fuzzy_prompt": "#a78bfa bold",
    "fuzzy_info": "#64748b",
    "fuzzy_border": "#334155",
    "fuzzy_match": "#38bdf8 bold",
    "instruction": "#64748b",
    "long_instruction": "#64748b",
}


def _menu_name(cat: str, lbl: str, desc: str, has_cat: bool) -> str:
    """Render one menu row as aligned columns: [CATEGORY] label · description."""
    catcol = f"{(cat or ''):<7}" if has_cat else ""
    return f"{catcol}{lbl:<19}{desc}" if desc else f"{catcol}{lbl}"


def _pick(message: str, items: list, default: str = None):
    """Fuzzy, type-to-filter selector (fzy / fzf-style). `items` = ``(value, label, desc)`` or
    ``(value, label, desc, category)`` — a category groups + aligns rows into a left column.
    **Esc** returns None (go back); **Ctrl+C** bubbles up to quit. Falls back to a numbered,
    grouped Rich prompt when a fuzzy TTY isn't available (or TG_NO_FUZZY is set)."""
    has_cat = any(len(it) > 3 and it[3] for it in items)
    if sys.stdin.isatty() and console.is_terminal and not os.environ.get("TG_NO_FUZZY"):
        try:
            from InquirerPy import inquirer
            from InquirerPy.base.control import Choice
            choices = [Choice(value=it[0],
                              name=_menu_name(it[3] if len(it) > 3 else "", it[1], it[2], has_cat))
                       for it in items]
            return inquirer.fuzzy(
                message=message, choices=choices, border=True, style=_MENU_STYLE,
                max_height="70%", cycle=True, pointer="❯", marker="›", qmark="›", amark="›",
                mandatory=False, keybindings={"skip": [{"key": "escape"}]},   # Esc → skip → None (back)
                instruction="(type to filter · ↑↓ move · enter select)",
                long_instruction="Esc = back      Ctrl+C = quit",
            ).execute()
        except Exception:  # TTY / import issue → numbered fallback (Ctrl+C bubbles, not caught here)
            pass
    console.print(Text(f"\n{message}", style=f"bold {PURPLE}"))
    last_cat = None
    for it in items:
        v, lbl, d = it[0], it[1], it[2]
        cat = it[3] if len(it) > 3 else ""
        if has_cat and cat != last_cat:
            console.print(Text(f"\n  {cat}", style="bold #64748b"))
            last_cat = cat
        console.print(Text.assemble((f"  {v:>2}  ", f"bold {BLUE}"), (lbl.ljust(18), "bold white"), (d, "dim")))
    console.print(Text("\n  Ctrl+C = quit", style="dim"))
    keys = [it[0] for it in items]
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
            console.print(Text.assemble(("  → ", f"bold {BLUE}"), (tools.docker_hint(), "dim")))
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
    url: str = typer.Argument(None, help="URL of the app to scan (your own / authorized). Omit + use --pick to choose from your scope."),
    pick: bool = typer.Option(False, "--pick", help="Pick the target from your authorized scope instead of typing a URL."),
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
    if pick or (not url and not json_out):
        from . import clients
        chosen = clients.pick_target(console)   # authorized, in-scope target (or None)
        if not chosen:
            raise typer.Exit()
        url = chosen
    if not url:
        console.print("[#f87171]No target — pass a URL or use --pick to choose from your scope.[/]")
        raise typer.Exit(1)
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
        console.print(Text.assemble(("  → ", f"bold {BLUE}"), (tools.docker_hint(), "dim")))
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
        console.print(Text.assemble(("  → ", f"bold {BLUE}"), (tools.docker_hint(), "dim")))
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
    ("temple-guard scan --pick", "pick the target from your authorized scope"),
    ("temple-guard monitor", "live dashboard — run several scans at once ('n' add · Esc leave)"),
    ("temple-guard monitor <urls…> --deep", "preload targets + the Docker recon set"),
    ("temple-guard monitor <urls…> --tools nmap", "preload specific Docker tools"),
    ("temple-guard monitor <urls…> -o report.html", "one combined report across all scans"),
    ("temple-guard tool", "list the Docker tools"),
    ("temple-guard tool <name>", "full explainer for a tool (what · how · risks · flags)"),
    ("temple-guard tool nmap <args>", "run a Kali tool with your own flags (full arg set)"),
    ("temple-guard tool nmap --dry-run", "preview the docker command for a tool; run nothing"),
    ("temple-guard tool nmap -h", "the tool's own help / full options"),
    ("temple-guard osint <target>", "OSINT / HUMINT footprint — domain · name · email · phone"),
    ("temple-guard apitest <url>", "discover API endpoints + bounded posture checks"),
    ("temple-guard strix <target>", "autonomous vulnerability validation (Strix, live)"),
    ("temple-guard strix <target> --scan-mode standard", "fuller validation pass"),
    ("temple-guard strix <target> --scan-mode deep --budget 5", "deep pass, cap LLM spend at $5"),
    ("temple-guard strix <target> --scope-mode diff --diff-base main", "validate only what changed (pre-merge)"),
    ("temple-guard strix <target> --dry-run", "print the strix command (key redacted), run nothing"),
    ("temple-guard strix import <path>", "ingest a strix_runs/ report → remediation"),
    ("temple-guard config llm", "connect an LLM provider for Strix (OAuth / API key)"),
    ("temple-guard client", "manage clients · engagements · authorized scope"),
    ("temple-guard scope list", "list every authorized in-scope target"),
    ("temple-guard playbook list", "list the ordered scan recipes"),
    ("temple-guard playbook run web-audit <url>", "run a playbook end-to-end → one report"),
    ("temple-guard pentest <url> --tests native,nmap,nuclei", "run selected tests against a target"),
    ("temple-guard pentest --pick", "pick tests + scoped target(s) → combined report"),
    ("temple-guard shell", "interactive Kali shell in a container"),
    ("temple-guard shell --dry-run", "preview the shell container command; start nothing"),
    ("temple-guard doctor", "check Docker + which tool images are present"),
    ("temple-guard doctor --pull", "pre-pull the Docker tool images for deep scans"),
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
        console.print(Text.assemble(("  ", ""), (cmd.ljust(50), f"{BLUE}"), (desc, "dim")))


def _scan_flow(deep: bool = False, dry: bool = False) -> None:
    """Prompt for a target + options, run the scan (+ Docker tools if deep), offer to save.
    In dry mode: print the checks + tool commands that would run, and run nothing."""
    from . import clients
    url = ""
    if clients.all_targets():
        console.print(Text.assemble(("  Tip: ", f"bold {BLUE}"),
                      ("pick from your authorized scope, or choose Back to type a URL.", "dim")))
        url = clients.pick_target(console) or ""
    if not url:
        url = Prompt.ask(f"[{BLUE}]Target URL[/] "
                         f"[dim](e.g. https://beta.example.com — blank = back)[/]").strip()
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
        console.print(Text.assemble(("  → ", f"bold {BLUE}"), (tools.docker_hint(), "dim")))
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
            {"ask": "Scan options — pick any (all safe & read-only)", "multi": [
                ("-sV   service + version detection", ["-sV"]),
                ("-sC   default safe NSE scripts", ["-sC"]),
                ("-O    OS detection", ["-O"]),
                ("--reason  show why each port's state was decided", ["--reason"]),
                ("-T4   faster timing", ["-T4"]),
                ("-v    verbose", ["-v"])]},
            {"ask": "Ports", "choices": [
                ("top 200 — default", ["--top-ports", "200"]), ("top 1000", ["--top-ports", "1000"]),
                ("range 1-1000", ["-p", "1-1000"]), ("all 65535 (slow)", ["-p-"])]},
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
    """Numbered pick from (label, tokens) pairs; default = first, 'b' = back.
    Returns the tokens, or None to go back."""
    console.print(Text(f"\n{prompt}", style=f"bold {BLUE}"))
    for i, (label, _tokens) in enumerate(choices, 1):
        console.print(Text.assemble((f"  {i}  ", f"bold {BLUE}"), (label, "white")))
    console.print(Text("  b  ← back", style="dim"))
    idx = Prompt.ask("Pick", choices=[str(i) for i in range(1, len(choices) + 1)] + ["b"], default="1")
    return None if idx == "b" else choices[int(idx) - 1][1]


def _ask_multi(prompt: str, choices: list) -> list:
    """MULTI-select from (label, tokens) pairs — pick any combination. Returns the concatenated
    tokens of everything selected (empty if none). Fuzzy checkbox when available, else a
    comma-separated numbered prompt."""
    if sys.stdin.isatty() and console.is_terminal and not os.environ.get("TG_NO_FUZZY"):
        try:
            from InquirerPy import inquirer
            from InquirerPy.base.control import Choice
            picked = inquirer.checkbox(
                message=prompt,
                choices=[Choice(value=i, name=lbl) for i, (lbl, _t) in enumerate(choices)],
                instruction="(space toggles · ↑↓ move · enter confirms · none = skip)",
                border=True, cycle=True, qmark="›", amark="›",
            ).execute()
            out: list = []
            for i in (picked or []):
                out += choices[i][1]
            return out
        except Exception:  # noqa: BLE001 — no fuzzy TTY → numbered fallback
            pass
    console.print(Text(f"\n{prompt}", style=f"bold {BLUE}"))
    for i, (label, _tokens) in enumerate(choices, 1):
        console.print(Text.assemble((f"  {i}  ", f"bold {BLUE}"), (label, "white")))
    raw = Prompt.ask("Pick [dim](comma-separated numbers, or blank for none)[/]", default="").strip()
    out = []
    for tok in raw.replace(",", " ").split():
        if tok.isdigit() and 1 <= int(tok) <= len(choices):
            out += choices[int(tok) - 1][1]
    return out


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
                         f"[dim](e.g. {tgt.get('eg', 'example.com')} — blank = back)[/]").strip()
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
            toks = _ask_choice(step["ask"], step["choices"])
            if toks is None:        # 'b' → back out of the guided flow
                return None
            argv += toks
        elif "multi" in step:       # multi-select — pick any combination of safe flags
            argv += _ask_multi(step["ask"], step["multi"])
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
            console.print(Text.assemble(("  → ", f"bold {BLUE}"), (tools.docker_hint(), "dim")))
            return
    picker = [(k, t.name, t.desc) for k, t in tools.TOOLS.items()]
    picker.append(("__back__", "← Back to menu", ""))
    name = _pick("Which tool?", picker, default="nmap")
    if not name or name == "__back__":   # None = Esc
        console.print("[dim]Back to the menu.[/]")
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
def monitor(
    urls: list[str] = typer.Argument(None, help="Targets to preload; or add them in the dashboard with 'n'."),
    workers: int = typer.Option(4, "--workers", "-w", help="Max scans running at once."),
    report: str = typer.Option(None, "--report", "-o",
                               help="Write ONE combined report (.html/.md/.json) for all scans when the run ends."),
    deep: bool = typer.Option(False, "--deep",
                              help="Also run the Docker recon set on preloaded targets (whatweb, wafw00f, testssl, nmap, nuclei)."),
    tools: str = typer.Option(None, "--tools",
                              help="Comma-separated Docker tools to also run on preloaded targets (e.g. nmap,nuclei)."),
):
    """Live dashboard — run several scans at once; add / stop / restart from inside it.

    Each target picks what runs against it (native checks, deep, or specific tools) — from
    the 'n' prompt in the dashboard, or via --deep / --tools for preloaded targets.

    temple-guard monitor                                       # open empty, add targets with 'n'
    temple-guard monitor https://a.example.com https://b.example.com -o report.html
    temple-guard monitor https://a.example.com --deep          # preload with the deep recon set
    """
    from . import monitor as _mon
    targets = [_norm_target(u, "url") for u in (urls or []) if u and u.strip()]
    tool_set = list(_mon.DEEP_TOOLS) if deep else []
    for tok in (tools.replace(",", " ").split() if tools else []):
        tok = tok.strip().lower()
        if tok in _mon.MONITOR_TOOLS and tok not in tool_set:
            tool_set.append(tok)
        elif tok:
            console.print(f"[yellow]unknown tool '{tok}' — skipping "
                          f"(known: {', '.join(_mon.MONITOR_TOOLS)})[/]")
    _mon.run(targets, workers=workers, report_path=report, tools=tool_set)


def _monitor_flow() -> None:
    _authz_notice()
    console.print(Text.assemble(
        ("Opening the monitor — press ", "dim"), ("n", f"bold {BLUE}"), (" to add targets, ", "dim"),
        ("w", f"bold {BLUE}"), (" for a combined report, ", "dim"),
        ("Esc", f"bold {BLUE}"), (" to leave (confirms if scans are running).", "dim")))
    from . import monitor as _mon
    _mon.run([], workers=4)


def _strix_doctor(docker_ok: bool) -> None:
    """Strix preflight section for `doctor`: is strix on PATH? Docker running? an LLM
    provider connected? Each with actionable guidance (mirrors tools.docker_hint())."""
    from . import strix as _strix
    console.print(Text("\n  Strix — autonomous vulnerability validation:", style="white"))
    if not _strix.STRIX_CAN_LAUNCH:
        console.print(Text.assemble(
            ("    ○ ", "#fbbf24"),
            ("live validation is a private-build / hosted feature — this build imports reports only "
             "(temple-guard strix import <path>).", "dim")))
        return
    for name, okr, detail, hint in _strix.preflight(docker_ok):
        console.print(Text.assemble(
            ("    " + ("✓ " if okr else "○ "), f"{'#4ade80' if okr else '#fbbf24'}"),
            (f"{name:<16}", "white"), (detail, "dim")))
        if not okr and hint:
            console.print(Text.assemble(("        → ", f"bold {BLUE}"), (hint, "dim")))


def _doctor(pull: bool = False) -> None:
    """Check Docker readiness + tool-image status; optionally pull the missing images."""
    from rich.prompt import Confirm
    console.print(Text.assemble(("\nTemple Guard — preflight for the Docker tools\n", f"bold {PURPLE}")))
    ok, why = tools.docker_available()
    console.print(Text.assemble(("  native checks   ", "white"),
                                ("✓ always available (no Docker needed)", "#4ade80")))
    console.print(Text.assemble(("  docker          ", "white"),
                                (("✓ ready" if ok else f"✗ {why}"), f"bold {'#4ade80' if ok else '#f87171'}")))
    _strix_doctor(ok)
    if not ok:
        console.print(Text.assemble(("\n  → ", f"bold {BLUE}"), (tools.docker_hint(), "white")))
        console.print(Text("\n  Native scans still work:  temple-guard scan <url>", style="dim"))
        raise typer.Exit(code=1)

    console.print(Text("\n  tool images:", style="white"))
    imgs = tools.defensive_images()
    missing = []
    for img in imgs:
        present = tools.image_present(img)
        if not present:
            missing.append(img)
        console.print(Text.assemble(
            ("    " + ("✓ " if present else "○ "), f"{'#4ade80' if present else '#fbbf24'}"),
            (f"{img:<34}", "white"), (("present" if present else "not pulled yet"), "dim")))

    if missing and not pull and console.is_terminal:
        pull = Confirm.ask(f"\n  Pull {len(missing)} missing image(s) now?", default=True)
    if pull and missing:
        console.print(Text(f"\n  pulling {len(missing)} image(s) — this can take a few minutes…", style="dim"))
        failed = 0
        for img in missing:
            with console.status(Text(f"docker pull {img}", style="dim"), spinner="dots"):
                okp, msg = tools.pull_image(img)
            if okp:
                console.print(Text.assemble(("    ✓ ", "#4ade80"), (img, "white"), ("  pulled", "dim")))
            else:
                failed += 1
                console.print(Text.assemble(("    ✗ ", "#f87171"), (img, "white"), (f"  {msg}", "dim")))
        if failed:
            console.print(Text.assemble((f"\n  {failed} image(s) failed to pull. ", "bold #f87171"),
                                        (tools.docker_hint(), "dim")))
            raise typer.Exit(code=1)
        console.print(Text("\n  ✓ all set — deep scans will run immediately.", style="bold #4ade80"))
    elif missing:
        console.print(Text.assemble((f"\n  {len(missing)} image(s) pull on first use. ", "dim"),
                                    ("Pre-pull now:  ", "dim"),
                                    ("temple-guard doctor --pull", f"bold {BLUE}")))
    else:
        console.print(Text("\n  ✓ all tool images present — deep scans will run immediately.",
                           style="bold #4ade80"))


@app.command()
def doctor(pull: bool = typer.Option(False, "--pull", help="Pull any missing Docker tool images now.")):
    """Preflight the Docker tools: verify Docker is running and fetch the tool images.

    temple-guard doctor            # check Docker + which tool images are present
    temple-guard doctor --pull     # + download any missing images up front
    """
    _doctor(pull=pull)


# ── OSINT / HUMINT ────────────────────────────────────────────────────────────
@contextlib.contextmanager
def _live_tool(label: str, image: str = None):
    """Wrap a blocking Docker tool call with a live spinner + elapsed clock so it never looks
    hung. If the image isn't cached yet, show a distinct 'pulling image' phase first (Docker
    pulls on demand — a tool's first run can take minutes, especially under emulation)."""
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    cols = (SpinnerColumn(style=PURPLE), TextColumn("{task.description}"), TimeElapsedColumn())
    if image:
        try:
            missing = not tools.image_present(image)
        except Exception:  # noqa: BLE001
            missing = False
        if missing:
            with Progress(*cols, console=console, transient=True) as p:
                p.add_task(f"[bold white]{label}[/]  ·  pulling [dim]{image}[/] "
                           f"[dim](first run — can take a few minutes)[/]", total=None)
                try:
                    tools.pull_image(image)
                except Exception:  # noqa: BLE001 — the run below surfaces any real error
                    pass
    with Progress(*cols, console=console, transient=True) as p:
        p.add_task(f"[bold white]{label}[/]  ·  running…", total=None)
        yield


def _run_osint(target: str, which: list, json_out: bool):
    """Run the chosen OSINT tools against a raw target and collect findings into a ScanResult."""
    from .checks import ScanResult
    res = ScanResult(url=target, reachable=True)
    for key in which:
        image = getattr(tools.recon_tools.RECON_TOOLS.get(key), "image", None)
        if not json_out:
            console.print(Text.assemble(("● ", f"bold {PURPLE}"), (f"{key}", "bold white")))
        try:
            if json_out:
                findings, _raw, _ok = tools.recon_tools.run_recon(key, target)
            else:
                with _live_tool(key, image):
                    findings, _raw, _ok = tools.recon_tools.run_recon(key, target)
        except Exception as exc:  # noqa: BLE001
            msg = f"{key} error — {str(exc)[:70]}"
            print(msg, file=sys.stderr) if json_out else console.print(f"[#f87171]  {msg}[/]")
            continue
        res.findings.extend(findings)
        if not json_out:
            n_hi = sum(1 for f in findings if f.severity in ("high", "medium"))
            console.print(Text.assemble((f"    {len(findings)} finding(s)", f"{BLUE}"),
                                        (f" · {n_hi} notable" if n_hi else "", "dim")))
            for f in findings:
                console.print(Text.assemble((f"    {f.severity.upper():4} ", SEV_STYLE.get(f.severity, "dim")),
                                            (f.title[:72], "white")))
    return res


@app.command("osint")
def osint_cmd(
    target: str = typer.Argument(..., help="Domain, name, email, or phone number — yours / authorized."),
    with_tools: str = typer.Option(None, "--tools",
                                   help="OSINT tools to run (comma list). Default: theharvester,subfinder,spiderfoot "
                                        "for a domain/name; phoneinfoga for a phone."),
    report: Path = typer.Option(None, "--report", "-o", help="Write a report (.html/.pdf/.md/.json)."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable findings."),
    no_anim: bool = typer.Option(False, "--no-anim", help="Disable the banner animation."),
):
    """OSINT / HUMINT footprint of a domain, person, email, or phone — passive, read-only public-source recon.

    temple-guard osint example.com
    temple-guard osint "Jane Doe" --tools spiderfoot
    temple-guard osint +14155552671            # phone → phoneinfoga
    """
    from . import recon_tools
    ok, why = tools.docker_available()
    if not ok:
        console.print(Text.assemble(("✗ Docker unavailable: ", "bold #f87171"), (why, "dim")))
        console.print(Text.assemble(("  → ", f"bold {BLUE}"), (tools.docker_hint(), "dim")))
        raise typer.Exit(1)
    is_phone = bool(re.fullmatch(r"\+?[0-9][0-9\s().-]{6,}", target.strip()))
    default = ["phoneinfoga"] if is_phone else ["theharvester", "subfinder", "spiderfoot"]
    which = default
    if with_tools:
        picked = [t.strip() for t in with_tools.replace(",", " ").split() if t.strip()]
        which = [t for t in picked if t in recon_tools.OSINT] or default
    if not json_out:
        _banner(animate=not no_anim)
        _authz_notice()
        console.print(Text.assemble(("\nOSINT ", f"bold {PURPLE}"), (target, "bold white"),
                                    (f"   ·   {', '.join(which)}", "dim")))
        amd = [t for t in which if t in getattr(recon_tools, "AMD64_ONLY", [])]
        if amd:
            console.print(Text(f"  ({', '.join(amd)} are amd64-only — slower under emulation on Apple Silicon)", style="dim"))
    res = _run_osint(target, which, json_out)
    if json_out:
        print(json.dumps(_result_dict(res), indent=2))
        raise typer.Exit(code=1 if res.by_severity.get("high") else 0)
    console.print()
    render(res, console)
    if report:
        _write_report(res, report)
    raise typer.Exit(code=1 if res.by_severity.get("high") else 0)


# ── API testing ───────────────────────────────────────────────────────────────
@app.command("apitest")
def apitest_cmd(
    url: str = typer.Argument(..., help="Base URL of the API to test — yours / authorized."),
    spec: str = typer.Option(None, "--spec",
                             help="OpenAPI/Swagger spec URL if it's at a non-standard path (e.g. /v3/api-docs)."),
    endpoints: str = typer.Option(None, "--endpoints",
                                  help="Comma-list of known routes to test directly, e.g. /users,/orders/1."),
    report: Path = typer.Option(None, "--report", "-o", help="Write a report (.html/.pdf/.md/.json)."),
    verbose: bool = typer.Option(False, "--verbose", "-v",
                                 help="Stream discovery — every path tried + its status — and each finding live."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable findings (+ discovery probes)."),
    no_anim: bool = typer.Option(False, "--no-anim", help="Disable the banner animation."),
):
    """Discover an API's endpoints (OpenAPI/Swagger or probing) + run bounded, read-only posture checks.

    No spec + non-standard routes (nothing discovered)? Point it at your spec, or list routes yourself:
      temple-guard apitest https://api.example.com --spec https://api.example.com/v3/api-docs
      temple-guard apitest https://api.example.com --endpoints /users,/orders,/health -v
    """
    from .apitest import run_api_test
    manual = [{"method": "GET", "path": (s if s.startswith("/") else "/" + s)}
              for s in (endpoints.replace(",", " ").split() if endpoints else []) if s]
    if not json_out:
        _banner(animate=not no_anim)
        _authz_notice()
        console.print()

    def _probe_log(kind, path, status):
        if not verbose or json_out:
            return
        colour = ("#4ade80" if 200 <= status < 300 else
                  "#fbbf24" if status in (401, 403, 405) else
                  "#f87171" if status else "dim")
        note = ("  (exists · protected)" if status in (401, 403)
                else "  (exists)" if 200 <= status < 300 else "")
        console.print(Text.assemble(("      ", ""), (f"{kind:5} ", "dim"), (path.ljust(22), "white"),
                                    (f"→ {status or 'err'}", colour), (note, "dim")))

    printer = make_progress_reporter(console) if (verbose and not json_out) else None
    result = run_api_test(url, on_event=printer, on_probe=_probe_log,
                          spec_url=spec, manual_endpoints=manual or None)
    if json_out:
        d = _result_dict(result)
        d["endpoints"] = getattr(result, "endpoints", [])
        d["probes"] = getattr(result, "probes", [])
        print(json.dumps(d, indent=2))
        raise typer.Exit(code=1 if result.by_severity.get("high") else 0)
    n = len(getattr(result, "endpoints", []))
    n_probes = len(getattr(result, "probes", []))
    console.print(Text.assemble(("Discovered ", "dim"), (f"{n} endpoint(s)", f"bold {BLUE}"),
                                (f"  ·  {n_probes} path(s) probed  ·  testing a bounded subset", "dim")))
    render(result, console)
    if report:
        _write_report(result, report)
    raise typer.Exit(code=1 if result.by_severity.get("high") else 0)


# ── clients / engagements / authorized scope ──────────────────────────────────
client_app = typer.Typer(add_completion=False, no_args_is_help=False,
                         help="Manage clients, engagements & authorized scope.")
# ── Strix — autonomous vulnerability validation (defensive) ───────────────────
def _strix_dry_run(target: str, *, scan_mode: str, scope_mode: str, diff_base: str,
                   instruction: str, budget=None, mount: str = None) -> None:
    """Print the exact `strix` invocation (+ the env it would inject, KEY REDACTED),
    and run nothing. Credentials go via env at spawn, never on argv."""
    from . import strix as _strix
    argv = _strix.strix_argv(target, scan_mode=scan_mode, scope_mode=scope_mode,
                             diff_base=diff_base, instruction=instruction, budget=budget, mount=mount)
    _dry_cmd("Strix validation", argv)
    env = _strix.redacted_env_display()
    if env:
        console.print(Text("  env (injected at spawn — never on the command line):", style="dim"))
        for k, v in env.items():
            console.print(Text.assemble(("    ", ""), (f"{k}=", f"{BLUE}"), (v, "dim")))
    else:
        console.print(Text("  (no provider connected yet — run `temple-guard config llm`)", style="dim"))
    console.print(Text("  ↑ credentials are passed via environment, not the command line.", style="dim italic"))


def _run_strix_live(target: str, *, scan_mode: str, scope_mode: str, diff_base: str,
                    instruction: str, budget=None, mount: str = None, quiet: bool = False):
    """Run Strix live behind a spinner (mirrors `_live_tool`) whose label tracks the
    current phase, starting with a 'pulling sandbox image' phase on first run.
    Parsed findings print above the bar as they land."""
    from . import strix as _strix
    if quiet:
        return _strix.run_strix(target, scan_mode=scan_mode, scope_mode=scope_mode,
                                diff_base=diff_base, instruction=instruction, budget=budget, mount=mount)
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    with Progress(SpinnerColumn(style=PURPLE), TextColumn("{task.description}"),
                  TimeElapsedColumn(), console=console, transient=True) as prog:
        task = prog.add_task("[bold white]Strix validation[/]  ·  starting…", total=None)

        def on_event(kind: str, **k) -> None:
            if kind == "phase":
                prog.update(task, description=f"[bold white]Strix validation[/]  ·  {k.get('name', '…')}")
            elif kind == "finding":
                f = k["finding"]
                prog.console.print(Text.assemble(
                    (f"  {f.severity.upper():4} ", SEV_STYLE.get(f.severity, "dim")),
                    (f.title[:74], "white")))
            elif kind == "error":
                prog.console.print(Text.assemble(("  ✗ ", "bold #f87171"), (k.get("message", "")[:110], "#f87171")))

        return _strix.run_strix(target, scan_mode=scan_mode, scope_mode=scope_mode,
                                diff_base=diff_base, instruction=instruction, budget=budget,
                                mount=mount, on_event=on_event)


def _strix_import(path, *, report=None, json_out: bool = False, no_anim: bool = False) -> None:
    """`strix import <path>` — ingest an existing strix_runs/ output → remediation view.
    Available in BOTH builds (touches no target)."""
    from . import strix as _strix
    if not path:
        console.print("[#f87171]Usage: temple-guard strix import <strix_runs path>[/]")
        console.print("[dim]  Point it at a strix_runs/<run-name>/ directory (or a findings .json / .md).[/]")
        raise typer.Exit(1)
    result = _strix.import_report(str(path))
    if json_out:
        print(json.dumps(_result_dict(result), indent=2))
        raise typer.Exit(code=1 if result.by_severity.get("high") else 0)
    _banner(animate=not no_anim)
    _authz_notice()
    console.print(Text.assemble(("\nImported Strix report  ", f"bold {PURPLE}"), (str(path), "dim")))
    console.print()
    render(result, console)
    if report:
        _write_report(result, Path(report))
    raise typer.Exit(code=1 if result.by_severity.get("high") else 0)


@app.command("strix")
def strix_cmd(
    target: str = typer.Argument(None, help="Target to validate (URL / directory / git-repo) — your own / authorized. "
                                            "Use `strix import <path>` to ingest an existing report instead."),
    path: str = typer.Argument(None, help="With `import`: the strix_runs/ report path to ingest."),
    pick: bool = typer.Option(False, "--pick", help="Pick the target from your authorized scope."),
    scan_mode: str = typer.Option("quick", "--scan-mode", "-m",
                                  help="quick (lighter, default) | standard (fuller) | deep (exhaustive)."),
    scope_mode: str = typer.Option(None, "--scope-mode",
                                   help="auto (default) | diff (only what changed — pre-merge/PR) | full."),
    diff_base: str = typer.Option(None, "--diff-base", help="Base branch for --scope-mode diff (e.g. main)."),
    instruction: str = typer.Option(None, "--instruction", help="Natural-language focus for the validation."),
    budget: float = typer.Option(None, "--budget", help="LLM cost cap in USD (Strix --max-budget-usd)."),
    mount: str = typer.Option(None, "--mount",
                              help="Read-only mount a local code repo into the sandbox (local targets)."),
    report: Path = typer.Option(None, "--report", "-o", help="Write a report (.html/.pdf/.md/.json)."),
    json_out: bool = typer.Option(False, "--json", help="Emit findings as JSON (no styling)."),
    dry_run: bool = typer.Option(False, "--dry-run",
                                 help="Print the exact strix invocation (key redacted); run nothing."),
    no_anim: bool = typer.Option(False, "--no-anim", help="Disable the banner animation."),
):
    """Autonomous vulnerability **validation** — confirm real weaknesses in an app you own,
    prove they're genuine, and get prioritized remediation (powered by a user-installed Strix).

    temple-guard strix https://app.example.com                  validate live (private build)
    temple-guard strix https://app.example.com --scan-mode standard
    temple-guard strix . --scope-mode diff --diff-base main      validate only what changed
    temple-guard strix https://app.example.com --dry-run         print the command, run nothing
    temple-guard strix import ./strix_runs/my-run               ingest a report → remediation
    """
    from . import strix as _strix

    # `strix import <path>` — emulated subcommand (Typer groups can't carry a positional
    # target alongside real subcommands). Works in BOTH builds.
    if target == "import":
        _strix_import(path, report=report, json_out=json_out, no_anim=no_anim)
        return

    # Launch tier (§6.3 / §10): without the private strix_ext unlock we NEVER spawn strix.
    if not _strix.STRIX_CAN_LAUNCH:
        console.print(Text.assemble(
            ("Live Strix validation is a private-build / hosted feature.", "bold #fbbf24")))
        console.print(Text.assemble(
            ("  In this build you can ingest a report you generated elsewhere:  ", "dim"),
            ("temple-guard strix import <path>", f"bold {BLUE}")))
        raise typer.Exit(0)

    if pick or (not target and not json_out):
        from . import clients
        chosen = clients.pick_target(console)
        if not chosen:
            raise typer.Exit()
        target = chosen
    if not target:
        console.print("[#f87171]No target — pass one or use --pick to choose from your scope.[/]")
        raise typer.Exit(1)
    if scan_mode not in _strix.SCAN_MODES:
        console.print(f"[#f87171]--scan-mode must be one of: {', '.join(_strix.SCAN_MODES)}[/]")
        raise typer.Exit(1)
    if scope_mode is not None and scope_mode not in _strix.SCOPE_MODES:
        console.print(f"[#f87171]--scope-mode must be one of: {', '.join(_strix.SCOPE_MODES)}[/]")
        raise typer.Exit(1)

    if not json_out:
        _banner(animate=not no_anim and not dry_run)
        _authz_notice()
        console.print()

    if dry_run:
        _strix_dry_run(target, scan_mode=scan_mode, scope_mode=scope_mode,
                       diff_base=diff_base, instruction=instruction, budget=budget, mount=mount)
        raise typer.Exit()

    # Preflight the launch path (mirror tools.docker_hint style guidance).
    if not _strix.strix_path():
        console.print(Text.assemble(("✗ Strix not installed: ", "bold #f87171"),
                                    (_strix.strix_hint(), "dim")))
        raise typer.Exit(1)
    llm_ok, _llm = _strix.llm_status()
    if not llm_ok:
        console.print(Text.assemble(("✗ No LLM provider connected. ", "bold #f87171"),
                                    ("Connect one:  ", "dim"), ("temple-guard config llm", f"bold {BLUE}")))
        raise typer.Exit(1)

    # Consent gate (§6.4) — a live validation EXECUTES against the target, distinct from a read-only
    # scan; the wording escalates with scan-mode and surfaces the $ budget cap.
    provider = _strix.llm_env().get("STRIX_LLM") or "the connected provider"
    if not json_out:
        depth = {"quick": "a lighter pass", "standard": "a fuller pass",
                 "deep": "a deep, exhaustive pass"}.get(scan_mode, "a pass")
        budget_note = f", capped at ${budget}" if budget is not None else ""
        console.print(Text.assemble(
            ("⚠ ", "bold #fbbf24"),
            (f"Strix will run live in its own sandbox against {target} ({depth}{budget_note}) and send "
             f"its data to {provider} to validate findings.", "italic #fbbf24")))
        if not Confirm.ask("[#fbbf24]I own or am authorized to test this target. Validate it?[/]", default=False):
            console.print("[dim]Cancelled — nothing was launched.[/]")
            raise typer.Exit()

    result = _run_strix_live(target, scan_mode=scan_mode, scope_mode=scope_mode,
                             diff_base=diff_base, instruction=instruction, budget=budget,
                             mount=mount, quiet=json_out)
    if json_out:
        print(json.dumps(_result_dict(result), indent=2))
        raise typer.Exit(code=1 if result.by_severity.get("high") else 0)
    console.print()
    render(result, console)
    if report:
        _write_report(result, report)
    raise typer.Exit(code=1 if result.by_severity.get("high") else 0)


def _strix_import_flow(dry: bool = False) -> None:
    """Menu flow: ingest an existing strix_runs/ report → remediation view."""
    from . import strix as _strix
    raw = Prompt.ask(f"[{BLUE}]Path to a Strix report[/] "
                     f"[dim](a strix_runs/<run> dir, or a .json/.md — blank = back)[/]").strip()
    if not raw:
        console.print("[dim]No path — back to the menu.[/]")
        return
    if dry:
        console.print(Text.assemble(("\nWould ingest ", "dim"), (raw, f"bold {BLUE}"),
                                    (" → remediation report — nothing sent.", "dim")))
        return
    result = _strix.import_report(raw)
    console.print()
    render(result, console)


def _strix_flow(dry: bool = False) -> None:
    """Menu flow: validate a target live (private build) or import an existing report."""
    from . import strix as _strix
    from . import clients
    if _strix.STRIX_CAN_LAUNCH:
        which = _pick("Strix — validate & harden:", [
            ("validate", "Validate a target", "run Strix live in its sandbox → proven findings + fixes"),
            ("import", "Import a report", "ingest an existing strix_runs/ output → remediation"),
            ("__back__", "← Back", ""),
        ], default="validate")
        if not which or which == "__back__":
            return
    else:
        console.print(Text("Live validation is a private-build / hosted feature — importing an existing report.",
                           style="dim"))
        which = "import"
    if which == "import":
        _strix_import_flow(dry)
        return

    # validate (launch) flow
    url = ""
    if clients.all_targets():
        console.print(Text.assemble(("  Tip: ", f"bold {BLUE}"),
                      ("pick from your authorized scope, or choose Back to type a target.", "dim")))
        url = clients.pick_target(console) or ""
    if not url:
        url = Prompt.ask(f"[{BLUE}]Target to validate[/] "
                         f"[dim](URL / dir / git-repo — blank = back)[/]").strip()
    if not url:
        console.print("[dim]No target — back to the menu.[/]")
        return
    # Strix accepts a URL, a local directory, or a git-repo URL — only tidy a bare web host.
    first = url.split("/", 1)[0]
    if "://" not in url and "." in first and not Path(url).exists():
        url = _norm_target(url, "url")
    mode = Prompt.ask("Scan mode", choices=["quick", "standard", "deep"], default="quick")
    instruction = Prompt.ask("[dim]Focus / instruction (optional — blank for none)[/]", default="").strip() or None
    budget_raw = Prompt.ask("[dim]LLM budget cap in USD (optional — blank for none)[/]", default="").strip()
    try:
        budget = float(budget_raw) if budget_raw else None
    except ValueError:
        budget = None
    if dry:
        console.print()
        _strix_dry_run(url, scan_mode=mode, scope_mode=None, diff_base=None,
                       instruction=instruction, budget=budget)
        return
    if not _strix.strix_path():
        console.print(Text.assemble(("✗ Strix not installed: ", "bold #f87171"), (_strix.strix_hint(), "dim")))
        return
    llm_ok, _llm = _strix.llm_status()
    if not llm_ok:
        console.print(Text.assemble(("✗ No LLM provider connected. ", "bold #f87171"),
                                    ("Connect one:  ", "dim"), ("temple-guard config llm", f"bold {BLUE}")))
        return
    provider = _strix.llm_env().get("STRIX_LLM") or "the connected provider"
    depth = {"quick": "a lighter pass", "standard": "a fuller pass",
             "deep": "a deep, exhaustive pass"}.get(mode, "a pass")
    budget_note = f", capped at ${budget}" if budget is not None else ""
    console.print(Text.assemble(
        ("⚠ ", "bold #fbbf24"),
        (f"Strix will run live in its own sandbox against {url} ({depth}{budget_note}) and send its "
         f"data to {provider}.", "italic #fbbf24")))
    if not Confirm.ask("[#fbbf24]I own or am authorized to test this target. Validate it?[/]", default=False):
        console.print("[dim]Cancelled — nothing was launched.[/]")
        return
    console.print()
    result = _run_strix_live(url, scan_mode=mode, scope_mode=None, diff_base=None,
                             instruction=instruction, budget=budget)
    console.print()
    render(result, console)


# ── config — model providers & credentials (for Strix) ────────────────────────
config_app = typer.Typer(add_completion=False, no_args_is_help=True,
                         help="Configure model providers & credentials for Strix validation.")
app.add_typer(config_app, name="config")


def _config_llm_flow() -> None:
    """Interactive: pick a provider → (OAuth-first scaffold) → paste an API key →
    store securely at ~/.temple-guard/llm.json (chmod 600). The key is never logged."""
    from datetime import datetime, timezone

    from . import strix as _strix
    console.print(Text("\nConnect a model provider for Strix validation", style=f"bold {PURPLE}"))
    console.print(Text("  Strix sends your app's data to this provider to power validation. Credentials are "
                       "stored at ~/.temple-guard/llm.json (chmod 600) and never logged.", style="dim"))
    items = [(k, label, model) for k, label, model, _url, _nb in _strix.PROVIDERS]
    items.append(("__back__", "← Back", ""))
    key = _pick("Which provider?", items, default="anthropic")
    if not key or key == "__back__":
        return
    _pk, label, default_model, url, needs_base = next(p for p in _strix.PROVIDERS if p[0] == key)

    # OAuth-first scaffold — Anthropic first (§4.2). Not built yet (needs live verification);
    # the API-key paste path below fully works today.
    if key in _strix.OAUTH_FIRST:
        console.print(Text.assemble(("\n  ", ""), (label, "bold white")))
        # TODO(oauth): bridge OAuth->API key, Anthropic first (§4.2). Ship OAuth device/sign-in
        # flow here, then set LLM_API_KEY from the resulting credential; verify LiteLLM/Strix
        # accepts it. Until then, fall through to the key-paste path.
        console.print(Text("  OAuth sign-in (like Claude Code) is coming soon; paste an API key for now.",
                           style="dim italic"))
    if url:
        console.print(Text.assemble(("  Get a key: ", "dim"), (url, f"{BLUE}")))

    model = Prompt.ask(f"[{BLUE}]Model[/] [dim](STRIX_LLM — LiteLLM `provider/model`)[/]",
                       default=default_model).strip() or default_model
    api_base = None
    if needs_base:
        api_base = Prompt.ask(f"[{BLUE}]API base URL[/] "
                              f"[dim](e.g. http://localhost:11434 for Ollama; blank = provider default)[/]",
                              default="").strip() or None
    # password=True hides input; the value is never echoed or logged.
    api_key = Prompt.ask(f"[{BLUE}]API key[/] [dim](paste — hidden; stored 0600, never logged)[/]",
                         password=True).strip()
    if key == "local" and not api_key:
        api_key = "ollama"  # local endpoints ignore the key; a placeholder keeps the pipeline valid
    if not api_key:
        console.print("[#f87171]No key entered — nothing saved.[/]")
        return

    cfg = {"provider": key, "model": model, "api_key": api_key, "api_base": api_base,
           "updated": datetime.now(timezone.utc).isoformat()}
    path = _strix.save_llm_config(cfg)
    console.print(Text.assemble(("\n✓ saved ", "bold #4ade80"), (label, "bold white"),
                                (f"   → {path}  (chmod 600)", "dim")))
    console.print(Text.assemble(("  model  ", "dim"), (model, f"{BLUE}")))
    console.print(Text("  Verify:  temple-guard doctor", style="dim"))


@config_app.command("llm")
def config_llm():
    """Connect an LLM provider for Strix — OAuth-first where available, API-key paste fallback.

    temple-guard config llm       # pick a provider, paste a key, stored 0600
    """
    _config_llm_flow()


# ── clients / engagements / authorized scope ──────────────────────────────────
client_app = typer.Typer(add_completion=False, no_args_is_help=False,
                         help="Manage clients, engagements & authorized scope.")


app.add_typer(client_app, name="client")


@client_app.callback(invoke_without_command=True)
def _client_default(ctx: typer.Context):
    if ctx.invoked_subcommand is None:      # bare `client` → interactive manager
        from . import clients
        clients.manage(console)


@client_app.command("list")
def client_list():
    """Show the clients → engagements → scope tree."""
    from . import clients
    clients.overview(console)


@client_app.command("add")
def client_add(name: str = typer.Argument(..., help="Client name."),
               notes: str = typer.Option("", "--notes", help="Free-text notes.")):
    """Add a client."""
    from . import clients
    c = clients.add_client(name, notes=notes)
    console.print(Text.assemble(("✓ client ", f"bold {BLUE}"), (c.name, "bold white"), (f"  [{c.slug}]", "dim")))


@client_app.command("engagement")
def client_engagement(
    client: str = typer.Argument(..., help="Client slug or name."),
    name: str = typer.Argument(..., help="Engagement name."),
    scope: str = typer.Option(None, "--scope", help="Authorized target(s), space/comma separated."),
    authorize: bool = typer.Option(False, "--authorize",
                                   help="Mark authorized — only then are its targets scannable."),
    roe: str = typer.Option("", "--roe", help="Rules-of-engagement note."),
):
    """Add an engagement (with optional scope + authorization) under a client."""
    from . import clients
    try:
        sc = [s.strip() for s in scope.replace(",", " ").split() if s.strip()] if scope else []
        e = clients.add_engagement(client, name, scope=sc, authorized=authorize, roe=roe)
    except ValueError as exc:
        console.print(f"[#f87171]✗ {exc}[/]")
        raise typer.Exit(1)
    console.print(Text.assemble(("✓ engagement ", f"bold {BLUE}"), (e.name, "bold white"),
                                (f"  [{e.slug}]  scope={len(e.scope)}  "
                                 f"{'authorized' if e.authorized else 'NOT authorized'}", "dim")))


scope_app = typer.Typer(add_completion=False, no_args_is_help=False,
                        help="View & manage authorized scope targets.")
app.add_typer(scope_app, name="scope")


@scope_app.command("list")
def scope_list():
    """List every authorized in-scope target."""
    from . import clients
    ts = clients.all_targets()
    if not ts:
        console.print("[dim]No authorized scope targets yet — add a client + engagement: "
                      "temple-guard client[/]")
        return
    for t in ts:
        console.print(Text.assemble(("  ● ", "#4ade80"), (t.target, "bold white"), (f"   {t.label}", "dim")))


@scope_app.command("add")
def scope_add(client: str = typer.Argument(..., help="Client slug or name."),
              engagement: str = typer.Argument(..., help="Engagement slug or name."),
              targets: list[str] = typer.Argument(..., help="Target(s) to add to the scope.")):
    """Add target(s) to an engagement's scope."""
    from . import clients
    try:
        e = clients.add_targets(client, engagement, list(targets))
    except ValueError as exc:
        console.print(f"[#f87171]✗ {exc}[/]  [dim](create it first: temple-guard client engagement …)[/]")
        raise typer.Exit(1)
    console.print(f"[green]✓ scope now {len(e.scope)} target(s) for {engagement}[/]")


@scope_app.command("authorize")
def scope_authorize(client: str = typer.Argument(...), engagement: str = typer.Argument(...),
                    revoke: bool = typer.Option(False, "--revoke", help="Revoke authorization instead.")):
    """Mark an engagement authorized (only then are its targets scannable) — or --revoke."""
    from . import clients
    try:
        clients.set_authorized(client, engagement, not revoke)
    except ValueError as exc:
        console.print(f"[#f87171]✗ {exc}[/]")
        raise typer.Exit(1)
    console.print(f"[green]✓ {engagement} {'revoked' if revoke else 'authorized'}[/]")


# ── playbooks — ordered, defensive multi-step scans ───────────────────────────
playbook_app = typer.Typer(add_completion=False, no_args_is_help=True,
                           help="Ordered, defensive multi-step scan recipes (recon → web → TLS …).")
app.add_typer(playbook_app, name="playbook")


@playbook_app.command("list")
def playbook_list():
    """List the playbooks and the steps each one chains, in order."""
    from . import playbooks
    console.print(Text("\nPlaybooks — ordered, read-only scan recipes:", style=f"bold {PURPLE}"))
    for pb in playbooks.CATALOG:
        console.print(Text.assemble(("  ● ", f"{BLUE}"), (pb.id.ljust(16), "bold white"), (pb.name, "white")))
        console.print(Text.assemble(("      ", ""), (pb.summary, "dim")))
    console.print(Text.assemble(("\n  Run one:  ", "dim"),
                                ("temple-guard playbook run <id> <url>", f"bold {BLUE}"),
                                ("   (or --pick a scoped target)", "dim")))


@playbook_app.command("run")
def playbook_run(
    playbook_id: str = typer.Argument(..., help="Playbook id — see `playbook list`."),
    url: str = typer.Argument(None, help="Target (your own / authorized). Omit + --pick to choose from scope."),
    pick: bool = typer.Option(False, "--pick", help="Pick the target from your authorized scope."),
    report: Path = typer.Option(None, "--report", "-o", help="Write a report (.html/.pdf/.md/.json)."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Stream each step + finding live."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable findings."),
    no_anim: bool = typer.Option(False, "--no-anim", help="Disable the banner animation."),
):
    """Run a playbook end-to-end against a target and print / save one merged report."""
    from . import playbooks
    pb = playbooks.get(playbook_id)
    if pb is None:
        console.print(Text.assemble(("✗ no such playbook: ", "bold #f87171"), (playbook_id, "white"),
                                    ("   (try `temple-guard playbook list`)", "dim")))
        raise typer.Exit(1)
    if pick or (not url and not json_out):
        from . import clients
        chosen = clients.pick_target(console)
        if not chosen:
            raise typer.Exit()
        url = chosen
    if not url:
        console.print("[#f87171]No target — pass one or use --pick to choose from your scope.[/]")
        raise typer.Exit(1)
    if not json_out:
        _banner(animate=not no_anim)
        _authz_notice()
        console.print(Text.assemble(("\n▶ ", f"bold {PURPLE}"), (pb.name, "bold white"), (f"   {pb.summary}", "dim")))
        console.print()
    printer = make_progress_reporter(console) if (verbose and not json_out) else None
    result = playbooks.run_playbook(pb, url, on_event=printer,
                                    tool_wrapper=(None if json_out else _live_tool))
    if json_out:
        print(json.dumps(_result_dict(result), indent=2))
        raise typer.Exit(code=1 if result.by_severity.get("high") else 0)
    render(result, console)
    if report:
        _write_report(result, report)
    raise typer.Exit(code=1 if result.by_severity.get("high") else 0)


def _playbook_flow(dry: bool = False) -> None:
    """Menu flow: pick a playbook + target, run the chain, show one merged report."""
    from . import playbooks, clients
    items = [(pb.id, pb.name, pb.summary) for pb in playbooks.CATALOG]
    items.append(("__back__", "← Back", ""))
    pid = _pick("Which playbook?", items, default=playbooks.CATALOG[0].id)
    if not pid or pid == "__back__":
        return
    pb = playbooks.get(pid)
    url = ""
    if clients.all_targets():
        console.print(Text.assemble(("  Tip: ", f"bold {BLUE}"),
                      ("pick from your authorized scope, or choose Back to type a target.", "dim")))
        url = clients.pick_target(console) or ""
    if not url:
        url = Prompt.ask(f"[{BLUE}]Target[/] [dim](domain or URL — blank = back)[/]").strip()
    if not url:
        console.print("[dim]No target — back to the menu.[/]")
        return
    if dry:
        console.print(Text.assemble(("\nWould run ", "dim"), (pb.name, f"bold {BLUE}"),
                                    (f" → {pb.summary}  against {url} — nothing sent.", "dim")))
        return
    if not Confirm.ask("[#fbbf24]I'm authorized to test this target. Run the playbook?[/]", default=True):
        console.print("[dim]Cancelled — nothing was sent.[/]")
        return
    console.print()
    result = playbooks.run_playbook(pb, url, on_event=make_progress_reporter(console),
                                    tool_wrapper=_live_tool)
    console.print()
    render(result, console)


# ── pentest — selectable tests across one or more targets → one combined report ─
_PENTEST_TESTS = [
    ("native",       "native", "built-in read-only checks (TLS · headers · cookies · info-leak · methods · SPF/DMARC)"),
    ("whatweb",      "tool",   "technology fingerprint"),
    ("wafw00f",      "tool",   "WAF / proxy detection"),
    ("nmap",         "tool",   "service / version discovery"),
    ("nuclei",       "tool",   "templated known-issue checks"),
    ("nikto",        "tool",   "web-server misconfiguration scan"),
    ("testssl",      "tool",   "TLS / cipher audit"),
    ("sslyze",       "recon",  "TLS protocol & cipher enumeration"),
    ("theharvester", "recon",  "emails / hosts / subdomains (OSINT)"),
    ("subfinder",    "recon",  "passive subdomain enumeration"),
    ("spiderfoot",   "recon",  "multi-source OSINT sweep"),
]
_PENTEST_KIND = {k: knd for k, knd, _l in _PENTEST_TESTS}
_PENTEST_ORDER = {k: i for i, (k, _knd, _l) in enumerate(_PENTEST_TESTS)}


def _pentest_steps(selected: list):
    """Turn selected test keys into ordered playbook steps (native → scan tools → recon)."""
    from . import playbooks
    steps = []
    for key in sorted(dict.fromkeys(selected), key=lambda k: _PENTEST_ORDER.get(k, 99)):
        knd = _PENTEST_KIND.get(key)
        if knd == "native":
            steps.append(playbooks.PlaybookStep("native"))
        elif knd in ("tool", "recon"):
            steps.append(playbooks.PlaybookStep(knd, key))
    return steps


def _write_combined(results: list, path: Path) -> None:
    """Write ONE report across every target's result — multi for html/md/json; single-target pdf supported."""
    from .report import to_html_multi, to_markdown_multi
    ext = path.suffix.lower()
    if ext == ".pdf" and len(results) == 1:
        _write_report(results[0], path)
        return
    if ext in (".html", ".htm"):
        path.write_text(to_html_multi(results, title="temple-guard — pentest report"))
        kind = "HTML"
    elif ext == ".json":
        path.write_text(json.dumps([_result_dict(r) for r in results], indent=2))
        kind = "JSON"
    else:
        path.write_text(to_markdown_multi(results, title="temple-guard — pentest report"))
        kind = "markdown"
    console.print(Text.assemble((f"\n✓ combined {kind} report ({len(results)} target(s)) → ", f"{BLUE}"),
                                (str(path), "bold white")))


@app.command()
def pentest(
    targets: list[str] = typer.Argument(None, help="Target(s) — your own / authorized. Omit + --pick to choose from scope."),
    tests: str = typer.Option(None, "--tests",
                              help="Comma-list: native,whatweb,wafw00f,nmap,nuclei,nikto,testssl,sslyze,"
                                   "theharvester,subfinder,spiderfoot. Interactive picker if omitted."),
    pick: bool = typer.Option(False, "--pick", help="Pick target(s) from your authorized scope."),
    report: Path = typer.Option(None, "--report", "-o",
                                help="Write ONE combined report (.html/.md/.json; .pdf for a single target)."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Stream each test + finding live."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable findings (a list, one entry per target)."),
    no_anim: bool = typer.Option(False, "--no-anim", help="Disable the banner animation."),
):
    """Run selectable, bounded tests against one or more targets → ONE combined report.

    temple-guard pentest https://app.example.com --tests native,nmap,nuclei
    temple-guard pentest --pick --tests native,testssl        # choose scoped targets
    temple-guard pentest                                       # fully interactive
    """
    from . import playbooks
    tlist = [t for t in (targets or []) if t]
    if pick or (not tlist and not json_out):
        from . import clients
        scoped = clients.all_targets()
        if scoped:
            tlist.extend(_ask_multi("Which target(s) from your authorized scope?",
                                    [(f"{st.target}   {st.label}", [st.target]) for st in scoped]))
        elif not tlist:
            console.print(Text.assemble(("No authorized scope targets. ", "bold #fbbf24"),
                          ("Add a client + engagement, or pass target URLs directly.", "dim")))
    tlist = list(dict.fromkeys(tlist))
    if not tlist:
        console.print("[#f87171]No targets — pass URL(s) or use --pick to choose from your scope.[/]")
        raise typer.Exit(1)

    valid = {k for k, _knd, _l in _PENTEST_TESTS}
    if tests:
        selected = [t for t in tests.replace(",", " ").split() if t in valid] or ["native"]
    elif json_out:
        selected = ["native"]
    else:
        console.print(Text("\nSelect the tests to run (all bounded & read-only):", style=f"bold {PURPLE}"))
        for k, _knd, lbl in _PENTEST_TESTS:
            console.print(Text.assemble(("  · ", f"{BLUE}"), (k.ljust(13), "bold white"), (lbl, "dim")))
        selected = _ask_multi("Which tests?", [(f"{k} — {lbl}", [k]) for k, _knd, lbl in _PENTEST_TESTS]) or ["native"]

    steps = _pentest_steps(selected)
    pb = playbooks.Playbook("pentest", "Pentest", "operator-selected tests", "custom", steps)
    if not json_out:
        _banner(animate=not no_anim)
        _authz_notice()
        console.print(Text.assemble(("\n▶ Pentest  ", f"bold {PURPLE}"),
                                    (f"{len(tlist)} target(s) × {len(steps)} test(s)", "bold white"),
                                    (f"   {pb.summary}", "dim")))
    printer = make_progress_reporter(console) if (verbose and not json_out) else None
    results = []
    for tgt in tlist:
        if not json_out:
            console.print(Text.assemble(("\n── ", "dim"), (tgt, f"bold {BLUE}"), (" ──", "dim")))
        results.append(playbooks.run_playbook(pb, tgt, on_event=printer,
                                              tool_wrapper=(None if json_out else _live_tool)))
    if json_out:
        print(json.dumps([_result_dict(r) for r in results], indent=2))
        raise typer.Exit(code=1 if any(r.by_severity.get("high") for r in results) else 0)
    console.print()
    for r in results:
        render(r, console)
    if report:
        _write_combined(results, report)
    raise typer.Exit(code=1 if any(r.by_severity.get("high") for r in results) else 0)


def _pentest_flow(dry: bool = False) -> None:
    """Menu flow: pick tests + target(s) from scope/typed, run them, show a combined report."""
    from . import playbooks, clients
    tlist = []
    if clients.all_targets():
        tlist.extend(_ask_multi("Target(s) from your scope  (pick none to type one instead)",
                                [(f"{st.target}   {st.label}", [st.target]) for st in clients.all_targets()]))
    if not tlist:
        raw = Prompt.ask(f"[{BLUE}]Target(s)[/] [dim](space/comma separated — blank = back)[/]").strip()
        tlist = [t for t in raw.replace(",", " ").split() if t]
    if not tlist:
        console.print("[dim]No targets — back to the menu.[/]")
        return
    console.print(Text("\nSelect the tests to run (all bounded & read-only):", style=f"bold {PURPLE}"))
    for k, _knd, lbl in _PENTEST_TESTS:
        console.print(Text.assemble(("  · ", f"{BLUE}"), (k.ljust(13), "bold white"), (lbl, "dim")))
    selected = _ask_multi("Which tests?", [(f"{k} — {lbl}", [k]) for k, _knd, lbl in _PENTEST_TESTS]) or ["native"]
    steps = _pentest_steps(selected)
    pb = playbooks.Playbook("pentest", "Pentest", "operator-selected tests", "custom", steps)
    if dry:
        console.print(Text.assemble(("\nWould run ", "dim"), (pb.summary, f"bold {BLUE}"),
                                    (f"  against {', '.join(tlist)} — nothing sent.", "dim")))
        return
    if not Confirm.ask("[#fbbf24]I'm authorized to test these target(s). Run the pentest?[/]", default=True):
        console.print("[dim]Cancelled — nothing was sent.[/]")
        return
    printer = make_progress_reporter(console)
    results = []
    for tgt in tlist:
        console.print(Text.assemble(("\n── ", "dim"), (tgt, f"bold {BLUE}"), (" ──", "dim")))
        results.append(playbooks.run_playbook(pb, tgt, on_event=printer, tool_wrapper=_live_tool))
    console.print()
    for r in results:
        render(r, console)


def _osint_flow(dry: bool = False) -> None:
    """Menu flow: OSINT / HUMINT footprint of a domain, name, email, or phone (passive, read-only)."""
    target = Prompt.ask(f"[{PURPLE}]OSINT target[/] "
                        f"[dim](domain · name · email · phone — blank = back)[/]").strip()
    if not target:
        console.print("[dim]No target — back to the menu.[/]")
        return
    from . import recon_tools
    is_phone = bool(re.fullmatch(r"\+?[0-9][0-9\s().-]{6,}", target))
    which = ["phoneinfoga"] if is_phone else ["theharvester", "subfinder", "spiderfoot"]
    if dry:
        console.print(Text.assemble(("\nWould run OSINT tools ", "dim"), (", ".join(which), f"bold {BLUE}"),
                                    (f" against {target} — nothing sent.", "dim")))
        return
    ok, why = tools.docker_available()
    if not ok:
        console.print(Text.assemble(("✗ Docker unavailable: ", "bold #f87171"), (why, "dim")))
        console.print(Text.assemble(("  → ", f"bold {BLUE}"), (tools.docker_hint(), "dim")))
        return
    if not Confirm.ask("[#fbbf24]I'm authorized to research this target. Run OSINT?[/]", default=True):
        console.print("[dim]Cancelled — nothing was sent.[/]")
        return
    console.print()
    res = _run_osint(target, which, json_out=False)
    console.print()
    render(res, console)


def _apitest_flow(dry: bool = False) -> None:
    """Menu flow: discover an API's endpoints + run bounded, read-only posture checks."""
    raw = Prompt.ask(f"[{BLUE}]API base URL[/] "
                     f"[dim](e.g. https://api.example.com — blank = back)[/]").strip()
    if not raw:
        console.print("[dim]No target — back to the menu.[/]")
        return
    url = _norm_target(raw, "url")
    if dry:
        console.print(Text.assemble(("\nWould discover endpoints + run bounded read-only checks against ", "dim"),
                                    (url, f"bold {BLUE}"), (" — nothing sent yet.", "dim")))
        return
    if not Confirm.ask("[#fbbf24]I'm authorized to test this API. Go?[/]", default=True):
        console.print("[dim]Cancelled — nothing was sent.[/]")
        return
    from .apitest import run_api_test
    console.print()
    result = run_api_test(url, on_event=make_progress_reporter(console))
    n = len(getattr(result, "endpoints", []))
    console.print(Text.assemble(("Discovered ", "dim"), (f"{n} endpoint(s)", f"bold {BLUE}"),
                                ("  ·  tested a bounded subset", "dim")))
    render(result, console)


@app.command()
def interactive() -> None:
    """Interactive, colourful menu — fuzzy-pick what to run. Esc = back · Ctrl+C = quit."""
    _banner(animate=True)
    _authz_notice()
    console.print(Text("  keys: type to filter · ↑↓ move · Enter select · Esc = back · Ctrl+C = quit",
                       style="dim"))
    dry = False
    try:
        while True:
            if dry:
                console.print(Text.assemble(
                    ("\n ● DRY-RUN ", "bold #fbbf24 reverse"),
                    ("  every action is previewed — nothing is sent or run.", "italic #fbbf24")))
            items = [
                ("1", "Scan a target", "read-only native checks", "SCAN"),
                ("2", "Deep scan", "native checks + Docker recon tools", "SCAN"),
                ("m", "Monitor", "live dashboard — run several scans at once", "SCAN"),
                ("o", "OSINT / HUMINT", "passive footprint — domain · name · email · phone", "RECON"),
                ("a", "API testing", "discover endpoints + bounded posture checks", "RECON"),
                ("b", "Playbooks", "ordered recon → web → TLS recipe", "RECON"),
                ("t", "Pentest", "pick tests + target(s) → one combined report", "RECON"),
                ("v", "Strix validate", "autonomous vulnerability validation → proven findings + fixes", "VALIDATE"),
                ("3", "Run a tool", "one Kali tool with your own arguments", "TOOLS"),
                ("4", "Kali shell", "interactive shell in a Kali container", "TOOLS"),
                ("c", "Clients & scope", "manage clients, engagements & authorized targets", "MANAGE"),
                ("p", "Doctor", "check Docker & pre-pull the tool images", "MANAGE"),
                ("5", "What it checks", "list the checks temple-guard runs", "INFO"),
                ("6", "Help", "commands & flags", "INFO"),
                ("7", "Update", "pull the newest temple-guard from its repo", "SYSTEM"),
                ("d", f"Dry-run: {'ON' if dry else 'OFF'}", "toggle preview-only mode for every action", "SYSTEM"),
                ("q", "Quit", "or Esc / Ctrl+C", "SYSTEM"),
            ]
            choice = _pick("What would you like to do?", items, default="1")

            if choice in (None, "q"):   # None = Esc at the top level → exit
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
            elif choice == "m":
                _monitor_flow()
            elif choice == "3":
                _tool_flow(dry=dry)
            elif choice == "4":
                _shell_flow(dry=dry)
            elif choice == "o":
                _osint_flow(dry=dry)
            elif choice == "a":
                _apitest_flow(dry=dry)
            elif choice == "c":
                from . import clients
                clients.manage(console)
            elif choice == "b":
                _playbook_flow(dry=dry)
            elif choice == "t":
                _pentest_flow(dry=dry)
            elif choice == "v":
                _strix_flow(dry=dry)
            elif choice == "p":
                _doctor()
            elif choice == "5":
                _print_checks()
            elif choice == "6":
                _print_commands()
            elif choice == "7":
                _do_update(check=True) if dry else _do_update()
    except KeyboardInterrupt:   # Ctrl+C anywhere in the session → clean quit
        console.print("\n[dim]Bye — stay safe out there.[/]")
        raise typer.Exit()


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

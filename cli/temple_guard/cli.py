"""temple-guard — scan your own web app and get a remediation report.

Authorized / self-assessment use only. Only scan applications you own or have
explicit written permission to test.
"""
from __future__ import annotations

import json
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

from . import __version__
from .checks import CHECK_PLAN, scan as run_scan
from .report import BLUE, PURPLE, make_progress_reporter, render, to_markdown, to_pdf

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
    [("╭─────────╮", SHIELD)],
    [("│", SHIELD), ("    ", None), ("╻", SABER), ("    ", None), ("│", SHIELD)],
    [("│", SHIELD), ("  ", None), ("╭─", MASK), ("╨", HILT), ("─╮", MASK), ("  ", None), ("│", SHIELD)],
    [("│", SHIELD), ("  ", None), ("┃", MASK), ("▚", EYE), (" ", None), ("▞", EYE), ("┃", MASK), ("  ", None), ("│", SHIELD)],
    [("│", SHIELD), ("  ", None), ("╰─", MASK), ("╥", HILT), ("─╯", MASK), ("  ", None), ("│", SHIELD)],
    [("╰╮", SHIELD), ("   ", None), ("┃", SABER), ("   ", None), ("╭╯", SHIELD)],
    [(" ", None), ("╰╮", SHIELD), ("  ", None), ("┃", SABER), ("  ", None), ("╭╯", SHIELD), (" ", None)],
    [("   ", None), ("╰─", SHIELD), ("┴", SABER), ("─╯", SHIELD), ("   ", None)],
]
_EMBLEM_W = 11


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
    """Run the scan — either verbose live progress, or a quiet spinner."""
    if verbose:
        console.print(Text.assemble(("▸ scanning ", f"bold {PURPLE}"), (url, f"bold {BLUE}")))
        result = run_scan(url, on_event=make_progress_reporter(console))
        console.print()
        return result
    with console.status(f"[{PURPLE}]scanning[/] {url} …", spinner="dots"):
        return run_scan(url)


def _write_report(result, path: Path) -> None:
    ext = path.suffix.lower()
    if ext == ".pdf":
        to_pdf(result, str(path))
        kind = "PDF"
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
                                help="Write a report; format follows the extension (.pdf / .json / .md)."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show each check + finding live as it runs."),
    json_out: bool = typer.Option(False, "--json", help="Emit findings as JSON (no styling)."),
    no_anim: bool = typer.Option(False, "--no-anim", help="Disable the banner animation."),
):
    """Run bounded, read-only defensive checks against URL and report what to fix."""
    if not json_out:
        _banner(animate=not no_anim and not dry_run)
        _authz_notice()
        console.print()

    if dry_run:
        _print_dry_run(url)
        raise typer.Exit()

    result = _run(url, verbose=verbose and not json_out)

    if json_out:
        print(json.dumps(_result_dict(result), indent=2))
        raise typer.Exit(code=1 if result.by_severity.get("high") else 0)

    render(result, console)
    if report:
        _write_report(result, report)
    # exit non-zero if any HIGH finding (handy for CI)
    raise typer.Exit(code=1 if result.by_severity.get("high") else 0)


@app.command()
def interactive() -> None:
    """Interactive, colourful session — choose a target and options, then scan."""
    _banner(animate=True)
    _authz_notice()
    console.print()

    console.print(Text("What temple-guard checks (all bounded & read-only):", style=f"bold {PURPLE}"))
    for cat, name, desc in CHECK_PLAN:
        console.print(Text.assemble(("  • ", f"{BLUE}"), (name, "bold white"), (f"   {desc}", "dim")))
    console.print()

    url = Prompt.ask(f"[{BLUE}]Target URL to scan[/] [dim](your own / authorized)[/]").strip()
    if not url:
        console.print("[dim]No target given — exiting.[/]")
        raise typer.Exit()

    if Confirm.ask("[dim]Dry run first (list checks, send nothing)?[/]", default=False):
        console.print()
        _print_dry_run(url)
        console.print()

    if not Confirm.ask("[#fbbf24]I'm authorized to test this target. Run the live scan?[/]", default=True):
        console.print("[dim]Cancelled — nothing was sent.[/]")
        raise typer.Exit()

    verbose = Confirm.ask("Show verbose live progress?", default=True)
    console.print()
    result = _run(url, verbose=verbose)
    render(result, console)

    fmt = Prompt.ask("Save a report?", choices=["no", "markdown", "pdf", "json"], default="no")
    if fmt != "no":
        ext = {"markdown": "md", "pdf": "pdf", "json": "json"}[fmt]
        path = Path(Prompt.ask("File path", default=f"temple-guard-report.{ext}"))
        _write_report(result, path)

    raise typer.Exit(code=1 if result.by_severity.get("high") else 0)


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

"""Live multi-scan monitor — a btop-style dashboard for concurrent self-scans.

Run several scans at once and watch them live: animated progress bars, a findings
meter, an activity sparkline, a status panel, and a live log stream. Stop / restart
individual scans, or queue new ones, without leaving the dashboard.

Real data only: each row is an actual `checks.scan()` running in its own thread;
progress and findings come from the scan's own event stream. No mock services.
"""
from __future__ import annotations

import itertools
import sys
import threading
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import tools as _tools
from .checks import CHECK_PLAN, scan as run_scan
from .report import BLUE, PURPLE

TOTAL_STEPS = len(CHECK_PLAN)
DEEP_TOOLS = list(_tools.DEFENSIVE)          # the `--deep` recon set: whatweb, wafw00f, testssl, nmap, nuclei
MONITOR_TOOLS = DEEP_TOOLS + ["nikto"]       # selectable per target in the dashboard (nikto is opt-in — slow)

GOLD = "#ffd60a"
TIP = "#fff7cc"
STEEL = "#94a3b8"
TRACK = "#242a36"
SEV_COLOR = {"high": "#f87171", "medium": "#fbbf24", "low": BLUE, "info": STEEL}
STATUS_COLOR = {"queued": STEEL, "running": BLUE, "done": "#4ade80",
                "failed": "#f87171", "stopped": "#fbbf24"}
LEVEL_COLOR = {"INF": BLUE, "WRN": "#fbbf24", "ERR": "#f87171"}


class _Stopped(Exception):
    """Raised inside a scan's event stream to abort it cooperatively."""


@dataclass
class Task:
    id: int
    url: str
    tools: list = field(default_factory=list)   # extra Docker tools to run after the native checks
    status: str = "queued"          # queued | running | done | failed | stopped
    step: int = 0                   # progress steps completed (0..total)
    current: str = "queued"
    findings: Counter = field(default_factory=Counter)
    started: float = 0.0
    ended: float = 0.0
    error: str = ""
    result: object = None            # the ScanResult (for the combined report)
    _stop: threading.Event = field(default_factory=threading.Event)

    @property
    def total(self) -> int:
        """Progress steps for this task: the native checks + one per selected Docker tool."""
        return TOTAL_STEPS + len(self.tools)

    @property
    def frac(self) -> float:
        tot = self.total
        if self.status == "done":
            return 1.0
        if self.status in ("failed", "stopped"):
            return self.step / tot if tot else 0.0
        return min(self.step / tot, 0.99) if tot else 0.0

    @property
    def age(self) -> float:
        if not self.started:
            return 0.0
        return (self.ended or time.monotonic()) - self.started

    @property
    def n_findings(self) -> int:
        return sum(self.findings.values())


class TaskManager:
    def __init__(self, workers: int = 4):
        self.tasks: list[Task] = []
        self._pool = ThreadPoolExecutor(max_workers=max(1, workers))
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self.log_lines: deque = deque(maxlen=500)
        self.started_at = time.monotonic()
        self._samples: deque = deque(maxlen=48)   # (t, total_findings) for the sparkline
        self._last_sample = 0.0

    def log(self, level: str, msg: str) -> None:
        self.log_lines.append((time.strftime("%H:%M:%S"), level, msg))

    def add(self, url: str, tools: list = None) -> Task:
        t = Task(id=next(self._ids), url=url, tools=list(tools or []))
        with self._lock:
            self.tasks.append(t)
        lbl = _profile_label(t)
        self.log("INF", f"queued  {url}" + (f"  ·  {lbl}" if lbl else ""))
        self._pool.submit(self._run, t)
        return t

    def stop(self, t: Task) -> None:
        if t.status in ("queued", "running"):
            t._stop.set()
            self.log("WRN", f"stopping {t.url}")

    def restart(self, t: Task) -> Task:
        self.log("INF", f"restart {t.url}")
        return self.add(t.url, t.tools)

    def _run(self, t: Task) -> None:
        t.status = "running"
        t.started = time.monotonic()
        t.current = "connecting"
        self.log("INF", f"scan start {t.url}")

        def on_event(kind: str, **k) -> None:
            if kind == "step":
                if t._stop.is_set():
                    raise _Stopped()
                t.step += 1
                t.current = k.get("name", "…")
            elif kind == "finding":
                f = k["finding"]
                t.findings[f.severity] += 1
                self.log(LEVEL_FOR_SEV.get(f.severity, "INF"),
                         f"{f.severity.upper():4} {t.url} · {f.title[:52]}")
            elif kind == "unreachable":
                self.log("ERR", f"unreachable {t.url}")

        try:
            res = run_scan(t.url, on_event=on_event)
            t.result = res
            if not res.reachable:
                t.status, t.error, t.current = "failed", (res.error or "unreachable"), "unreachable"
                self.log("ERR", f"failed  {t.url} — {t.error[:50]}")
            else:
                t.step = TOTAL_STEPS                       # native checks done
                if t.tools:
                    self._run_tools(t, res)                # then the selected Docker tools
                t.step, t.status, t.current = t.total, "done", "done"
                self.log("INF", f"done    {t.url} — {t.n_findings} findings")
        except _Stopped:
            t.status, t.current = "stopped", "stopped"
            self.log("WRN", f"stopped {t.url}")
        except Exception as exc:  # noqa: BLE001 — surface any scan error as a failed task
            t.status, t.error, t.current = "failed", str(exc), "error"
            self.log("ERR", f"error   {t.url} — {str(exc)[:50]}")
        t.ended = time.monotonic()

    def _run_tools(self, t: Task, res) -> None:
        """After the native checks, run each selected Docker tool and merge its findings
        into both the live counter and the ScanResult (so the combined report includes them)."""
        ok, why = _tools.docker_available()
        if not ok:
            self.log("ERR", f"docker unavailable — {len(t.tools)} tool(s) skipped: {why}")
            self.log("WRN", _tools.docker_hint())
            return
        for key in t.tools:
            if t._stop.is_set():
                raise _Stopped()
            t.current = key
            self.log("INF", f"tool    {t.url} · {key} …")
            try:
                findings, _raw, _ok = _tools.run_tool(key, t.url)
            except Exception as exc:  # noqa: BLE001 — one tool failing shouldn't sink the scan
                self.log("ERR", f"{key} error — {str(exc)[:50]}")
                t.step += 1
                continue
            for f in findings:
                t.findings[f.severity] += 1
                res.findings.append(f)
                self.log(LEVEL_FOR_SEV.get(f.severity, "INF"),
                         f"{f.severity.upper():4} {t.url} · {f.title[:52]}")
            t.step += 1

    def counts(self) -> Counter:
        return Counter(t.status for t in self.tasks)

    def findings_total(self) -> Counter:
        tot: Counter = Counter()
        for t in self.tasks:
            tot.update(t.findings)
        return tot

    def sample(self) -> None:
        now = time.monotonic()
        if now - self._last_sample >= 0.5:
            self._samples.append(sum(self.findings_total().values()))
            self._last_sample = now

    def all_settled(self) -> bool:
        return bool(self.tasks) and all(t.status in ("done", "failed", "stopped") for t in self.tasks)

    def shutdown(self) -> None:
        for t in self.tasks:
            t._stop.set()
        self._pool.shutdown(wait=False)


LEVEL_FOR_SEV = {"high": "ERR", "medium": "WRN", "low": "INF", "info": "INF"}


def _profile_label(t: Task) -> str:
    """A short tag for what runs against a target: '' (native only), 'deep', or the tool set."""
    if not t.tools:
        return ""
    if list(t.tools) == DEEP_TOOLS:
        return "deep"
    if len(t.tools) <= 2:
        return "+".join(t.tools)
    return f"{len(t.tools)} tools"


# ── rendering ────────────────────────────────────────────────────────────────
def _saber() -> Text:
    """A little gold lightsaber — a steel hilt (left) with a single blade extending out."""
    return Text.assemble(
        ("▪", STEEL),            # pommel cap
        ("▬▬", STEEL),           # hilt — a stubby steel rectangle (the grip)
        ("▮", GOLD),             # emitter — where the blade ignites
        ("━━━━━", GOLD),          # the blade
        ("╾", TIP),              # glowing tip
    )


def _fmt_age(secs: float) -> str:
    s = int(secs)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m"


def _bar(frac: float, width: int, color: str, running: bool, tick: int) -> Text:
    filled = round(frac * width)
    sweep = (tick % filled) if (running and filled) else -1   # a bright cell sweeping the filled part
    t = Text()
    for i in range(width):
        if i < filled:
            t.append("█", style="bold white" if i == sweep else color)
        elif i == filled and running:
            t.append("▌", style=f"bold {color}")
        else:
            t.append("─", style=TRACK)
    return t


def _meter(label: str, value: int, maxv: int, color: str, width: int = 14) -> Text:
    filled = int((value / maxv) * width) if maxv else 0
    return Text.assemble(
        (f"{label:4} ", "white"),
        ("█" * filled, color), ("─" * (width - filled), TRACK),
        (f" {value}", f"bold {color}"))


def _sparkline(vals: list[int], width: int = 40) -> Text:
    if len(vals) < 2:
        return Text("gathering…", style="dim")
    deltas = [max(0, b - a) for a, b in zip(vals, vals[1:])][-width:]
    if not any(deltas):
        deltas = [0] * len(deltas)
    blocks = " ▁▂▃▄▅▆▇█"
    hi = max(deltas) or 1
    t = Text()
    for d in deltas:
        t.append(blocks[int(d / hi * (len(blocks) - 1))], style=BLUE)
    return t


def _header(mgr: TaskManager) -> Text:
    up = _fmt_age(time.monotonic() - mgr.started_at)
    c = mgr.counts()
    return Text.assemble(
        ("  ", ""), _saber(),
        ("  temple-guard ", f"bold {PURPLE}"), ("monitor", f"bold {BLUE}"),
        (f"   uptime {up}", "dim"),
        (f"   ·   {len(mgr.tasks)} scans", "dim"),
        ("      ", ""),
        ("● ", STATUS_COLOR["running"]), (f"{c.get('running', 0)} running   ", "dim"),
        ("● ", STATUS_COLOR["done"]), (f"{c.get('done', 0)} done   ", "dim"),
        (time.strftime("%H:%M:%S"), "dim"))


def _findings_panel(mgr: TaskManager) -> Panel:
    tot = mgr.findings_total()
    maxv = max(tot.values()) if tot else 0
    rows = [_meter(lbl, tot.get(sev, 0), maxv, SEV_COLOR[sev])
            for lbl, sev in (("HIGH", "high"), ("MED", "medium"), ("LOW", "low"), ("INFO", "info"))]
    rows.append(Text.assemble((f"\n {sum(tot.values())} findings", f"bold {BLUE}"),
                              (f"  ·  {len(mgr.tasks)} scans", "dim")))
    return Panel(Group(*rows), title="findings", title_align="left", border_style="#334155", padding=(1, 1))


def _activity_panel(mgr: TaskManager, tick: int) -> Panel:
    spark = _sparkline(list(mgr._samples))
    c = mgr.counts()
    body = Group(
        Text("findings / time", style="dim"),
        spark,
        Text.assemble((f"\n {c.get('running', 0)} active", f"bold {BLUE}"),
                      (f"  ·  {c.get('done', 0)} complete", "dim")))
    return Panel(body, title="activity", title_align="left", border_style="#334155", padding=(1, 1))


def _status_panel(mgr: TaskManager) -> Panel:
    c = mgr.counts()
    grid = Table.grid(padding=(0, 2))
    grid.add_column(); grid.add_column(justify="right")
    grid.add_column(); grid.add_column(justify="right")
    order = [("running", "running"), ("queued", "queued"), ("done", "done"),
             ("failed", "failed"), ("stopped", "stopped")]
    cells = [(Text.assemble(("● ", STATUS_COLOR[k]), (label, "white")), Text(str(c.get(k, 0)), style="bold white"))
             for k, label in order]
    for i in range(0, len(cells), 2):
        left = cells[i]
        right = cells[i + 1] if i + 1 < len(cells) else (Text(""), Text(""))
        grid.add_row(left[0], left[1], right[0], right[1])
    return Panel(grid, title="status", title_align="left", border_style="#334155", padding=(1, 1))


def _scan_cell(t: Task) -> Text:
    """The SCAN column — what runs against this target: native / deep / the tool set."""
    if not t.tools:
        return Text("native", style="dim")
    if list(t.tools) == DEEP_TOOLS:
        return Text("deep", style=f"bold {GOLD}")
    if len(t.tools) == 1:
        return Text(t.tools[0][:8], style=GOLD)
    return Text(f"{t.tools[0][:4]}+{len(t.tools) - 1}", style=GOLD)


def _tasks_panel(mgr: TaskManager, sel: int, tick: int) -> Panel:
    tbl = Table(expand=True, box=None, pad_edge=False)
    tbl.add_column(" ", width=1)
    tbl.add_column("TARGET", style="white", no_wrap=True, ratio=3)
    tbl.add_column("SCAN", width=8, no_wrap=True)
    tbl.add_column("STATUS", width=8)
    tbl.add_column("PROGRESS", width=20)
    tbl.add_column("FINDINGS", width=12)
    tbl.add_column("AGE", width=6, justify="right")
    for i, t in enumerate(mgr.tasks):
        col = STATUS_COLOR[t.status]
        marker = Text("▸", style=f"bold {BLUE}") if i == sel else Text(" ")
        target = t.url.replace("https://", "").replace("http://", "")
        bar = _bar(t.frac, 14, col, t.status == "running", tick)
        prog = Text()
        prog.append_text(bar)
        prog.append(f" {int(t.frac * 100):3d}%", style=f"dim {col}")
        fnd = Text.assemble(
            (f"{t.findings.get('high', 0)}H ", SEV_COLOR["high"] if t.findings.get('high') else "dim"),
            (f"{t.findings.get('medium', 0)}M ", SEV_COLOR["medium"] if t.findings.get('medium') else "dim"),
            (f"{t.findings.get('low', 0)}L", SEV_COLOR["low"] if t.findings.get('low') else "dim"))
        row_style = "on #16202e" if i == sel else ""
        tbl.add_row(marker, Text(target, style=("bold white" if i == sel else "white")),
                    _scan_cell(t), Text(t.status, style=col), prog, fnd,
                    Text(_fmt_age(t.age), style="dim"), style=row_style)
    if not mgr.tasks:
        tbl.add_row("", Text("no scans yet — press  n  to add targets and pick a scan", style="dim"),
                    "", "", "", "", "")
    return Panel(tbl, title="[1] scans", title_align="left", border_style=BLUE, padding=(0, 1))


def _logs_panel(mgr: TaskManager, height: int) -> Panel:
    lines = list(mgr.log_lines)[-(max(height, 4)):]
    body = Text()
    for ts, level, msg in lines:
        body.append(f"{ts} ", style="dim")
        body.append(f"{level} ", style=f"bold {LEVEL_COLOR.get(level, 'white')}")
        body.append(msg + "\n", style="#cbd5e1")
    if not lines:
        body = Text("waiting for activity…", style="dim")
    return Panel(body, title="[2] logs · follow ▶", title_align="left", border_style="#334155", padding=(0, 1))


def _footer() -> Text:
    parts = [("↑↓/jk", "select"), ("s", "stop"), ("r", "restart"), ("n", "add"),
             ("w", "report"), ("esc", "quit")]
    t = Text("  ")
    for key, desc in parts:
        t.append(f" {key} ", style=f"bold {BLUE} reverse")
        t.append(f" {desc}   ", style="dim")
    return t


def _render(mgr: TaskManager, sel: int, tick: int, body_h: int) -> Layout:
    mgr.sample()
    layout = Layout()
    layout.split_column(
        Layout(_header(mgr), name="header", size=1),
        Layout(name="top", size=8),
        Layout(name="body", ratio=1),
        Layout(_footer(), name="footer", size=1))
    layout["top"].split_row(
        Layout(_findings_panel(mgr)), Layout(_activity_panel(mgr, tick)), Layout(_status_panel(mgr)))
    layout["body"].split_row(
        Layout(_tasks_panel(mgr, sel, tick), ratio=3), Layout(_logs_panel(mgr, body_h), ratio=2))
    return layout


# ── keyboard ─────────────────────────────────────────────────────────────────
class _Keys(threading.Thread):
    """Reads single keypresses (Unix cbreak) and mutates the shared state dict.

    While a line prompt is open (adding targets / naming a report) the reader must
    step aside — otherwise it keeps stdin in no-echo cbreak mode *and* consumes the
    keystrokes meant for the prompt. `pause()` restores cooked/echo mode and stops
    reading; `resume()` returns to single-key mode.
    """

    def __init__(self, state: dict, mgr: TaskManager):
        super().__init__(daemon=True)
        self.state, self.mgr = state, mgr
        self._pause = threading.Event()   # set → step aside for a line prompt
        self._acked = threading.Event()   # reader confirms it's in cooked mode

    def run(self) -> None:
        try:
            import select
            import termios
            import tty
        except ImportError:
            return  # no interactive controls on this platform (watch-only)
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while not self.state["quit"]:
                if self._pause.is_set():
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)   # cooked mode → prompts echo
                    self._acked.set()
                    while self._pause.is_set() and not self.state["quit"]:
                        time.sleep(0.05)
                    self._acked.clear()
                    if self.state["quit"]:
                        break
                    tty.setcbreak(fd)                               # back to single-key mode
                    continue
                if select.select([sys.stdin], [], [], 0.15)[0]:
                    if self._pause.is_set():
                        continue   # a prompt just opened — leave the byte for it
                    self._handle(sys.stdin.read(1), select, termios)
        except Exception:  # noqa: BLE001
            pass
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    def pause(self) -> None:
        """Restore cooked/echo mode and stop consuming stdin, for a line prompt."""
        if not self.is_alive():
            return
        self._acked.clear()
        self._pause.set()
        self._acked.wait(timeout=1.0)

    def resume(self) -> None:
        """Return to single-key (cbreak) mode after a line prompt."""
        self._pause.clear()

    def _handle(self, ch: str, select, termios) -> None:  # noqa: ANN001
        s, m = self.state, self.mgr
        n = len(m.tasks)
        if ch == "\x1b":  # a bare ESC, or the introducer of an arrow key (ESC[A or ESC O A)
            seq = ""
            while len(seq) < 6:
                # wait a touch longer for the FIRST follow-byte, then only briefly for the rest;
                # a real arrow arrives as one burst, a lone Esc yields nothing.
                if not select.select([sys.stdin], [], [], 0.12 if not seq else 0.03)[0]:
                    break
                c = sys.stdin.read(1)
                seq += c
                if (c.isalpha() or c == "~") and len(seq) >= 2:  # final byte of a CSI/SS3 seq
                    break
            if not seq:                       # nothing followed → a real Esc → request quit (gated)
                s["confirm_quit"] = True
                return
            final = seq[-1]
            if final == "A":                  # ↑ — works for both ESC[A and ESC O A (app-cursor mode)
                ch = "k"
            elif final == "B":                # ↓
                ch = "j"
            else:                             # ←/→, Home/End, F-keys, … — ignore, do NOT quit
                return
        if ch == "\x03":                      # Ctrl-C as a byte → request quit (gated)
            s["confirm_quit"] = True
        elif ch == "j" and n:
            s["sel"] = min(s["sel"] + 1, n - 1)
        elif ch == "k" and n:
            s["sel"] = max(s["sel"] - 1, 0)
        elif ch == "s" and n:
            m.stop(m.tasks[s["sel"]])
        elif ch == "r" and n:
            m.restart(m.tasks[s["sel"]])
        elif ch == "n":
            s["add"] = True
        elif ch == "w":
            s["report"] = True
        elif ch == "q":                       # q no longer quits — guide the user to Esc / Ctrl-C
            m.log("INF", "press Esc or Ctrl-C to leave the monitor")


# ── entry points ─────────────────────────────────────────────────────────────
def _norm(u: str) -> str:
    u = u.strip()
    if not u or "://" in u:
        return u
    host = u.split("/", 1)[0]
    local = host.split(":", 1)[0] in ("localhost", "127.0.0.1", "0.0.0.0") or ":" in host
    return ("http://" if local else "https://") + u


def _prompt_targets(console: Console) -> tuple:
    """Ask for one or more targets, then what should run against them.
    Returns (urls, tools) — `tools` is the extra Docker tool set (empty = native checks only)."""
    import re
    from rich.prompt import Prompt
    raw = Prompt.ask("[cyan]Targets[/] [dim](space/comma separated — "
                     "e.g. https://a.com https://b.com; blank to cancel)[/]").strip()
    urls = [_norm(u) for u in re.split(r"[\s,]+", raw) if u.strip()]
    if not urls:
        return [], []
    return urls, _prompt_profile(console, len(urls))


def _prompt_profile(console: Console, n_targets: int) -> list:
    """Pick what runs against the new target(s): native checks, the deep set, or chosen tools."""
    import re

    from rich.prompt import Prompt
    scope = f"these {n_targets} targets" if n_targets > 1 else "this target"
    console.print()
    console.print(f"  [bold]What should run against {scope}?[/]")
    console.print("    [bold]1[/] Native checks   [dim]— headers · TLS · cookies · exposure · "
                  "SPF/DMARC   (fast, no Docker)[/]")
    console.print(f"    [bold]2[/] Deep            [dim]— native + Docker recon: "
                  f"{', '.join(DEEP_TOOLS)}[/]")
    console.print("    [bold]3[/] Pick tools…     [dim]— native + specific Docker tools[/]")
    choice = Prompt.ask("  choose", choices=["1", "2", "3"], default="1")
    if choice == "1":
        return []
    if choice == "2":
        return list(DEEP_TOOLS)
    console.print()
    for i, key in enumerate(MONITOR_TOOLS, 1):
        console.print(f"    [bold]{i:>2}[/] {key:8} [dim]— {_tools.TOOLS[key].desc}[/]")
    raw = Prompt.ask("  tools [dim](numbers or names, comma/space separated; blank = native only)[/]",
                     default="").strip()
    picked: list = []
    for tok in re.split(r"[\s,]+", raw.lower()):
        tok = tok.strip()
        if not tok:
            continue
        key = MONITOR_TOOLS[int(tok) - 1] if (tok.isdigit() and 1 <= int(tok) <= len(MONITOR_TOOLS)) \
            else (tok if tok in MONITOR_TOOLS else None)
        if key and key not in picked:
            picked.append(key)
    return picked


def _prompt_report_path(console: Console) -> str:
    from rich.prompt import Prompt
    return Prompt.ask("[cyan]Save combined report to[/] [dim](.html / .md / .json)[/]",
                      default="temple-guard-monitor-report.html").strip()


def write_report(mgr: TaskManager, path: str):
    """Write ONE combined report across every scan that produced a result. Returns (n, Path|None)."""
    from pathlib import Path

    from . import report
    results = [t.result for t in mgr.tasks if getattr(t, "result", None) is not None]
    if not results:
        return 0, None
    p = Path(path)
    ext = p.suffix.lower()
    if ext == ".json":
        import json
        data = {"scans": [{"url": r.url, "reachable": r.reachable, "status": r.status,
                           "server": r.server, "error": r.error,
                           "findings": [f.__dict__ for f in r.findings]} for r in results]}
        p.write_text(json.dumps(data, indent=2))
    elif ext == ".md":
        p.write_text(report.to_markdown_multi(results))
    else:
        if ext not in (".html", ".htm"):
            p = p.with_suffix(".html")
        p.write_text(report.to_html_multi(results))
    return len(results), p


def _confirm_quit(mgr: TaskManager, console: Console) -> bool:
    """Ask before leaving the monitor. Returns True to quit, False to stay.
    Warns (and defaults to 'stay') when scans are still running."""
    from rich.prompt import Confirm
    c = mgr.counts()
    active = c.get("running", 0) + c.get("queued", 0)
    console.print()
    if active:
        console.print(Text.assemble(
            ("⚠ ", "bold #fbbf24"),
            (f"{active} scan(s) still running — leaving the monitor will stop them.", "#fbbf24")))
    try:
        return Confirm.ask("[bold]Quit the monitor?[/]", default=not active)
    except (KeyboardInterrupt, EOFError):
        return True   # a second Ctrl-C at the prompt → force quit


def _dashboard(mgr: TaskManager, urls: list, console: Console, report_path: str = None,
               tools: list = None) -> None:
    for u in urls:
        mgr.add(u, tools)
    state = {"sel": 0, "quit": False, "add": False, "report": False, "confirm_quit": False}
    keys = _Keys(state, mgr)
    keys.start()
    tick = 0
    body_h = max((console.size.height or 24) - 12, 6)
    try:
        with Live(console=console, screen=True, refresh_per_second=10, transient=True) as live:
            while not state["quit"]:
                try:
                    if state["confirm_quit"]:       # Esc / Ctrl-C → gated leave (are-you-sure)
                        state["confirm_quit"] = False
                        keys.pause()
                        live.stop()
                        if _confirm_quit(mgr, console):
                            state["quit"] = True
                            break
                        live.start(refresh=True)    # stayed — resume the dashboard
                        keys.resume()
                        continue
                    if state["add"]:                # 'n' — add one or more targets, mid-run
                        state["add"] = False
                        keys.pause()                # step the key-reader aside so typing echoes
                        live.stop()
                        new_urls, picked = _prompt_targets(console)
                        for u in new_urls:
                            mgr.add(u, picked)
                        live.start(refresh=True)
                        keys.resume()
                    if state["report"]:             # 'w' — write ONE combined report for all scans
                        state["report"] = False
                        keys.pause()
                        live.stop()
                        dest = _prompt_report_path(console)
                        if dest:
                            n, p = write_report(mgr, dest)
                            if n:
                                mgr.log("INF", f"wrote combined report ({n} scans) → {p}")
                                console.print(f"[green]✓ combined report ({n} scans) → {p}[/]")
                            else:
                                console.print("[dim]No completed scans to report yet.[/]")
                            time.sleep(1.4)
                        live.start(refresh=True)
                        keys.resume()
                    state["sel"] = min(state["sel"], max(len(mgr.tasks) - 1, 0))
                    live.update(_render(mgr, state["sel"], tick, body_h))
                    time.sleep(0.1)
                    tick += 1
                except KeyboardInterrupt:            # Ctrl-C anywhere in the loop → route to the gate
                    state["confirm_quit"] = True
    except KeyboardInterrupt:
        pass
    finally:
        state["quit"] = True
        mgr.shutdown()
    if report_path:
        n, p = write_report(mgr, report_path)
        if n:
            console.print(f"[green]✓ combined report ({n} scans) → {p}[/]")
    _summary(mgr, console)


def _summary(mgr: TaskManager, console: Console) -> None:
    c = mgr.counts()
    tot = mgr.findings_total()
    console.print(Text.assemble(
        ("\nMonitor closed — ", "dim"),
        (f"{len(mgr.tasks)} scans: ", "white"),
        (f"{c.get('done', 0)} done ", "#4ade80"),
        (f"{c.get('failed', 0)} failed ", "#f87171"),
        (f"{c.get('stopped', 0)} stopped", "#fbbf24"),
        (f"  ·  {sum(tot.values())} findings "
         f"({tot.get('high', 0)}H {tot.get('medium', 0)}M {tot.get('low', 0)}L)", "dim")))


def _headless(mgr: TaskManager, urls: list, console: Console, report_path: str = None,
              tools: list = None) -> None:
    """No-TTY fallback (pipes / CI): run the scans, print progress, then summarize."""
    for u in urls:
        mgr.add(u, tools)
    while not mgr.all_settled():
        c = mgr.counts()
        console.print(f"[dim]running {c.get('running', 0)} · done {c.get('done', 0)} · "
                      f"failed {c.get('failed', 0)}[/]")
        time.sleep(1.0)
    if report_path:
        n, p = write_report(mgr, report_path)
        if n:
            console.print(f"[green]✓ combined report ({n} scans) → {p}[/]")
    _summary(mgr, console)


def run(urls: list, workers: int = 4, report_path: str = None, tools: list = None) -> None:
    """Launch the live monitor. Open the dashboard (add targets with 'n'), or preload `urls`.
    `tools` is the extra Docker tool set applied to preloaded `urls` (empty = native checks only;
    inside the dashboard each target picks its own). `report_path`, if given, writes ONE combined
    report across all scans when the run ends."""
    console = Console()
    mgr = TaskManager(workers=workers)
    urls = [u for u in (urls or []) if u]
    if sys.stdin.isatty() and console.is_terminal:
        _dashboard(mgr, urls, console, report_path, tools)
    else:
        if not urls:
            console.print("[dim]No targets and no interactive terminal — nothing to monitor.[/]")
            return
        _headless(mgr, urls, console, report_path, tools)

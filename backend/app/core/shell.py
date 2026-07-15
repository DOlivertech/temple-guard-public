"""WebSocket ↔ PTY bridge for in-app remote terminals.

Two modes:
  * real     — `docker exec -it` into a running Kali container via a pty
  * emulated — a tiny line-based shell so the console UI works with no Docker

Wire protocol (browser ↔ server):
  * binary frame  -> raw stdin keystrokes (written to the pty)
  * text frame    -> JSON control message, e.g. {"resize":{"cols":120,"rows":30}}
"""
from __future__ import annotations

import asyncio
import fcntl
import json
import os
import pty
import signal
import struct
import subprocess
import termios

from fastapi import WebSocket, WebSocketDisconnect


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass


async def pty_bridge(ws: WebSocket, command: list[str], banner: str = "") -> None:
    """Bridge a websocket to a subprocess running on a pseudo-terminal."""
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        command, stdin=slave, stdout=slave, stderr=slave,
        preexec_fn=os.setsid, close_fds=True,
    )
    os.close(slave)
    if banner:
        await ws.send_text(banner)

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def on_readable() -> None:
        try:
            data = os.read(master, 8192)
        except OSError:
            data = b""
        queue.put_nowait(data or None)

    loop.add_reader(master, on_readable)

    async def pump_to_client() -> None:
        while True:
            data = await queue.get()
            if data is None:
                break
            try:
                await ws.send_bytes(data)
            except Exception:
                break

    out_task = asyncio.create_task(pump_to_client())
    try:
        while True:
            msg = await ws.receive()
            if msg.get("type") == "websocket.disconnect":
                break
            if msg.get("bytes") is not None:
                os.write(master, msg["bytes"])
            elif msg.get("text") is not None:
                text = msg["text"]
                try:
                    ctrl = json.loads(text)
                    if "resize" in ctrl:
                        _set_winsize(master, int(ctrl["resize"]["rows"]),
                                     int(ctrl["resize"]["cols"]))
                        continue
                except (ValueError, KeyError, TypeError):
                    pass
                os.write(master, text.encode())
    except WebSocketDisconnect:
        pass
    finally:
        loop.remove_reader(master)
        out_task.cancel()
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            proc.kill()
        os.close(master)


async def stream_logs(ws: WebSocket, command: list[str]) -> None:
    """Stream a `docker logs -f` (or similar) process to the websocket."""
    proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, bufsize=0)
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    fd = proc.stdout.fileno()

    def on_readable() -> None:
        try:
            data = os.read(fd, 4096)
        except OSError:
            data = b""
        queue.put_nowait(data or None)

    loop.add_reader(fd, on_readable)

    async def pump() -> None:
        while True:
            data = await queue.get()
            if data is None:
                break
            try:
                await ws.send_bytes(data)
            except Exception:
                break

    out_task = asyncio.create_task(pump())
    try:
        # Keep the socket alive; ignore client input (logs are read-only).
        while True:
            msg = await ws.receive()
            if msg.get("type") == "websocket.disconnect":
                break
    except WebSocketDisconnect:
        pass
    finally:
        loop.remove_reader(fd)
        out_task.cancel()
        try:
            proc.terminate()
        except Exception:
            pass


# ── Emulated shell (no Docker) ──────────────────────────────────────────────
_PROMPT = "\x1b[1;33m┌──(\x1b[1;36mtempleguard\x1b[1;33m㉿sim)-[\x1b[0m~\x1b[1;33m]\n└─\x1b[1;31m#\x1b[0m "

_FAKE_FS = {
    "help": "Simulated console. Real Kali shells appear here when an instance is\r\n"
            "provisioned with Docker. Try: ls, whoami, uname -a, nmap, cat /etc/os-release",
    "ls": "engagements/  loot/  wordlists/  README.txt",
    "whoami": "root",
    "uname -a": "Linux templeguard-sim 6.x kali (simulation) x86_64 GNU/Linux",
    "cat /etc/os-release": 'PRETTY_NAME="Kali GNU/Linux Rolling (simulated)"',
    "nmap": "Starting Nmap (simulated). Provision a real Kali instance for live scans.",
}


async def emulated_shell(ws: WebSocket, hostname: str = "sim") -> None:
    await ws.send_text(
        "\x1b[1;36m⛨ Temple Guard — simulated console\x1b[0m\r\n"
        "Docker not available or instance not running. Type 'help'.\r\n\r\n")
    await ws.send_text(_PROMPT)
    line = ""
    try:
        while True:
            msg = await ws.receive()
            if msg.get("type") == "websocket.disconnect":
                break
            data = msg.get("bytes")
            text = data.decode("utf-8", "ignore") if data is not None else msg.get("text", "")
            if text and text.startswith("{") and '"resize"' in text:
                continue
            for ch in text:
                if ch in ("\r", "\n"):
                    cmd = line.strip()
                    line = ""
                    await ws.send_text("\r\n")
                    if cmd in ("exit", "logout"):
                        await ws.send_text("logout\r\n")
                        return
                    if cmd:
                        out = _FAKE_FS.get(cmd, f"{cmd.split()[0]}: command not found "
                                                 f"(simulated shell)")
                        await ws.send_text(out + "\r\n")
                    await ws.send_text(_PROMPT)
                elif ch in ("\x7f", "\b"):
                    if line:
                        line = line[:-1]
                        await ws.send_text("\b \b")
                else:
                    line += ch
                    await ws.send_text(ch)  # local echo
    except WebSocketDisconnect:
        pass

"use client";
import { useEffect, useRef } from "react";
import { wsUrl } from "@/lib/api";

/**
 * xterm view over a backend WebSocket. Two modes:
 *   - shell  (default): bidirectional PTY — keystrokes sent, output rendered
 *   - readOnly (logs):  output-only stream (e.g. `docker logs -f`)
 *
 * Pass either `instanceId` (→ /instances/{id}/shell) or an explicit `wsPath`.
 */
export default function Terminal({
  instanceId, wsPath, readOnly = false, title, heightClass = "h-80",
}: {
  instanceId?: number;
  wsPath?: string;
  readOnly?: boolean;
  title?: string;
  heightClass?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const statusRef = useRef<HTMLSpanElement>(null);
  const path = wsPath ?? `/instances/${instanceId}/shell`;

  useEffect(() => {
    let term: any, fit: any, ws: WebSocket | null = null, disposed = false;
    let onResize: (() => void) | null = null;

    (async () => {
      const { Terminal: XTerm } = await import("xterm");
      const { FitAddon } = await import("xterm-addon-fit");
      await import("xterm/css/xterm.css");
      if (disposed || !ref.current) return;

      term = new XTerm({
        cursorBlink: !readOnly,
        disableStdin: readOnly,
        convertEol: true,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        fontSize: 12.5,
        theme: { background: "#0b1120", foreground: "#cbd5e1", cursor: "#38bdf8" },
      });
      fit = new FitAddon();
      term.loadAddon(fit);
      term.open(ref.current);
      fit.fit();

      const setStatus = (t: string, c: string) => {
        if (statusRef.current) { statusRef.current.textContent = t; statusRef.current.style.color = c; }
      };

      ws = new WebSocket(wsUrl(path));
      ws.binaryType = "arraybuffer";
      ws.onopen = () => {
        setStatus("● live", "#34d399");
        if (!readOnly) ws?.send(JSON.stringify({ resize: { cols: term.cols, rows: term.rows } }));
      };
      ws.onmessage = (e) => {
        if (typeof e.data === "string") term.write(e.data);
        else term.write(new Uint8Array(e.data));
      };
      ws.onclose = () => setStatus("● closed", "#f87171");
      ws.onerror = () => setStatus("● error", "#f87171");

      if (!readOnly) {
        term.onData((d: string) => {
          if (ws?.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(d));
        });
      }

      onResize = () => {
        try {
          fit.fit();
          if (!readOnly && ws?.readyState === WebSocket.OPEN)
            ws.send(JSON.stringify({ resize: { cols: term.cols, rows: term.rows } }));
        } catch {}
      };
      window.addEventListener("resize", onResize);
    })();

    return () => {
      disposed = true;
      if (onResize) window.removeEventListener("resize", onResize);
      try { ws?.close(); } catch {}
      try { term?.dispose(); } catch {}
    };
  }, [path, readOnly]);

  return (
    <div className="rounded-lg border border-edge bg-ink overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-edge bg-panel2">
        <span className="text-xs text-slate-400 font-mono">{title || (readOnly ? "logs" : "shell")}</span>
        <span ref={statusRef} className="text-xs" style={{ color: "#94a3b8" }}>● connecting…</span>
      </div>
      <div ref={ref} className={`${heightClass} p-2`} />
    </div>
  );
}

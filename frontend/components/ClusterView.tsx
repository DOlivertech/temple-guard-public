"use client";
import { useMemo } from "react";

export interface ClusterContainer {
  id: string; name: string; image: string; state: string; status: string;
  created: string; role: string; managed?: boolean;
  client_id?: number; engagement_id?: number; instance_id?: number;
  client_name?: string; engagement_name?: string;
  stats?: { cpu: string; mem: string; mem_pct: string } | null;
}

const pct = (s?: string) => {
  const n = parseFloat((s || "").replace("%", ""));
  return Number.isFinite(n) ? n : 0;
};
const ROLE_ICON: Record<string, string> = { kali: "🐉", scan: "⚙", external: "▢" };
const STATE = {
  running: { dot: "#34d399", ring: "#34d39955", text: "text-emerald-300" },
  exited: { dot: "#64748b", ring: "#33415533", text: "text-slate-400" },
  created: { dot: "#fbbf24", ring: "#fbbf2455", text: "text-amber-300" },
} as const;
const st = (s: string) => (STATE as any)[s] || STATE.exited;

/** Live "cluster map" of Temple Guard containers, grouped client → engagement
 *  (namespaces), with health colours and CPU/MEM gauges — a k8s-dashboard feel. */
export default function ClusterView({ containers, activeRef, pending, onSelect, onAct, onBulk }: {
  containers: ClusterContainer[];
  activeRef?: string;
  pending: string;
  onSelect: (ref: string, name: string, tab?: "logs" | "shell") => void;
  onAct: (ref: string, action: string) => void;
  onBulk: (action: string, scope: { client_id?: number; engagement_id?: number }) => void;
}) {
  const groups = useMemo(() => {
    const byClient: Record<string, { name: string; client_id?: number;
      engs: Record<string, { name: string; engagement_id?: number; items: ClusterContainer[] }> }> = {};
    for (const c of containers) {
      const ck = String(c.client_id ?? "none");
      const ek = String(c.engagement_id ?? "none");
      byClient[ck] ??= { name: c.client_name || (c.managed ? "Unassigned" : "External / Unmanaged"), client_id: c.client_id, engs: {} };
      byClient[ck].engs[ek] ??= { name: c.engagement_name || (c.managed ? "—" : "unmanaged"), engagement_id: c.engagement_id, items: [] };
      byClient[ck].engs[ek].items.push(c);
    }
    return byClient;
  }, [containers]);

  const running = containers.filter((c) => c.state === "running");
  const cpuAvg = running.length ? running.reduce((a, c) => a + pct(c.stats?.cpu), 0) / running.length : 0;
  const memPeak = containers.reduce((a, c) => Math.max(a, pct(c.stats?.mem_pct)), 0);

  return (
    <div className="space-y-4">
      {/* control-plane summary bar */}
      <div className="card p-3 flex items-center gap-5 flex-wrap bg-ink/60">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400/60" />
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-400" />
          </span>
          <span className="text-sm font-semibold">Cluster</span>
        </div>
        <Metric label="nodes" value={String(containers.length)} />
        <Metric label="running" value={String(running.length)} color="#34d399" />
        <Metric label="stopped" value={String(containers.length - running.length)} color="#64748b" />
        <div className="flex items-center gap-2 min-w-[140px]">
          <span className="label">cpu avg</span>
          <Bar value={cpuAvg} max={100} color="#38bdf8" />
          <span className="text-xs font-mono text-slate-300 w-10">{cpuAvg.toFixed(0)}%</span>
        </div>
        <div className="flex items-center gap-2 min-w-[140px]">
          <span className="label">mem peak</span>
          <Bar value={memPeak} max={100} color="#a855f7" />
          <span className="text-xs font-mono text-slate-300 w-10">{memPeak.toFixed(0)}%</span>
        </div>
      </div>

      {Object.entries(groups).length === 0 && (
        <div className="card p-6 text-sm text-slate-400">
          No managed containers. Launch a Kali instance from Consoles or run an audit — nodes appear here live.
        </div>
      )}

      {/* namespaces: client → engagement */}
      {Object.entries(groups).map(([ck, client]) => (
        <div key={ck} className="rounded-xl border border-edge bg-panel2/40 p-3">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <span className="text-accent">◉</span>
              <span className="font-semibold text-sm">{client.name}</span>
              <span className="chip text-[9px] text-slate-500">namespace</span>
            </div>
            {client.client_id && (
              <div className="flex gap-1.5">
                <button className="btn text-[10px] py-0.5" disabled={!!pending} onClick={() => onBulk("stop", { client_id: client.client_id })}>stop all</button>
                <button className="btn text-[10px] py-0.5" disabled={!!pending} onClick={() => onBulk("restart", { client_id: client.client_id })}>restart all</button>
              </div>
            )}
          </div>

          {Object.entries(client.engs).map(([ek, eng]) => (
            <div key={ek} className="rounded-lg border border-edge/60 bg-ink/40 p-2.5 mb-2 last:mb-0">
              <div className="flex items-center justify-between mb-2 px-0.5">
                <span className="text-[11px] text-slate-400">⛨ {eng.name}
                  <span className="text-slate-600"> · {eng.items.length} pod{eng.items.length !== 1 ? "s" : ""}</span>
                </span>
                {eng.engagement_id && (
                  <button className="text-[10px] text-slate-500 hover:text-white" disabled={!!pending}
                    onClick={() => onBulk("stop", { engagement_id: eng.engagement_id })}>stop ns</button>
                )}
              </div>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                {eng.items.map((c) => <Node key={c.id} c={c} active={activeRef === c.id} pending={pending} onSelect={onSelect} onAct={onAct} />)}
              </div>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

function Node({ c, active, pending, onSelect, onAct }: {
  c: ClusterContainer; active: boolean; pending: string;
  onSelect: (ref: string, name: string, tab?: "logs" | "shell") => void; onAct: (ref: string, action: string) => void;
}) {
  const s = st(c.state);
  const isRun = c.state === "running";
  return (
    <div onClick={() => onSelect(c.id, c.name)}
      className={`group rounded-lg border bg-panel2 p-2.5 cursor-pointer transition hover:border-accent ${active ? "border-accent" : ""}`}
      style={{ borderColor: active ? undefined : s.ring, boxShadow: isRun ? `0 0 0 1px ${s.ring} inset` : undefined }}>
      <div className="flex items-center gap-1.5">
        <span className="relative flex h-2 w-2">
          {isRun && <span className="animate-ping absolute inline-flex h-full w-full rounded-full" style={{ background: s.dot, opacity: 0.5 }} />}
          <span className="relative inline-flex rounded-full h-2 w-2" style={{ background: s.dot }} />
        </span>
        <span className="text-[10px]">{ROLE_ICON[c.role] || "▢"}</span>
        <span className="font-mono text-[11px] truncate flex-1" title={c.name}>{c.name}</span>
      </div>
      <div className="text-[9px] text-slate-500 font-mono truncate mt-1" title={c.image}>{c.image}</div>
      <div className="mt-2 space-y-1">
        <Gauge label="cpu" value={pct(c.stats?.cpu)} max={100} color="#38bdf8" text={c.stats?.cpu} />
        <Gauge label="mem" value={pct(c.stats?.mem_pct)} max={100} color="#a855f7" text={(c.stats?.mem || "").split("/")[0].trim()} />
      </div>
      <div className="flex items-center gap-1 mt-2 opacity-60 group-hover:opacity-100 transition" onClick={(e) => e.stopPropagation()}>
        {isRun
          ? <IconBtn t="■" title="stop" disabled={!!pending} onClick={() => onAct(c.id, "stop")} />
          : <IconBtn t="▶" title="start" disabled={!!pending} onClick={() => onAct(c.id, "start")} />}
        <IconBtn t="↻" title="restart" disabled={!!pending} onClick={() => onAct(c.id, "restart")} />
        <IconBtn t="≡" title="logs" onClick={() => onSelect(c.id, c.name, "logs")} />
        <IconBtn t="▮" title="shell" disabled={!isRun} onClick={() => onSelect(c.id, c.name, "shell")} />
        <span className="flex-1" />
        <IconBtn t="✕" title="remove" danger disabled={!!pending} onClick={() => onAct(c.id, "remove")} />
      </div>
    </div>
  );
}

function Gauge({ label, value, max, color, text }: { label: string; value: number; max: number; color: string; text?: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[8px] text-slate-500 w-6 uppercase">{label}</span>
      <Bar value={value} max={max} color={color} />
      <span className="text-[8px] font-mono text-slate-400 w-12 text-right truncate">{text || `${value.toFixed(0)}%`}</span>
    </div>
  );
}
function Bar({ value, max, color }: { value: number; max: number; color: string }) {
  const w = Math.max(2, Math.min(100, (value / max) * 100));
  return (
    <div className="flex-1 h-1.5 rounded-full bg-ink overflow-hidden">
      <div className="h-full rounded-full transition-all" style={{ width: `${w}%`, background: color }} />
    </div>
  );
}
function Metric({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <span className="text-lg font-semibold" style={{ color: color || "#fff" }}>{value}</span>
      <span className="label">{label}</span>
    </div>
  );
}
function IconBtn({ t, title, onClick, disabled, danger }: { t: string; title: string; onClick: () => void; disabled?: boolean; danger?: boolean }) {
  return (
    <button title={title} disabled={disabled} onClick={onClick}
      className={`text-[11px] w-6 h-6 grid place-items-center rounded border border-edge hover:border-accent disabled:opacity-30 ${danger ? "hover:border-red-500/60 hover:text-red-300" : ""}`}>
      {t}
    </button>
  );
}

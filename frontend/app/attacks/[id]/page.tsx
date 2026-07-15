"use client";
import { useMemo, useState } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import useSWR, { mutate } from "swr";
import ReactFlow, { Background, MarkerType, type Node, type Edge } from "reactflow";
import "reactflow/dist/style.css";
import { api, fetcher, SEV_COLOR } from "@/lib/api";
import type { Control } from "@/lib/types";
import { PageHeader, SevBadge, SevBar, ControlLinks, Spinner } from "@/components/ui";

const Terminal = dynamic(() => import("@/components/Terminal"), { ssr: false });

interface Attack {
  target: { id: number; kind: string; value: string; os?: string; label?: string };
  engagement_id: number; engagement_name?: string; client_name?: string;
  status: string; active_count: number;
  started_at?: string; finished_at?: string; duration_s?: number;
  scans: any[]; containers: any[]; findings: any[]; assets: any[];
  findings_by_severity: Record<string, number>;
}

const fmtDur = (s?: number | null) => s == null ? "—" : s < 60 ? `${s.toFixed(1)}s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
const fmtTime = (t?: string) => t ? new Date(t).toLocaleTimeString() : "—";

export default function AttackDashboard({ params }: { params: { id: string } }) {
  const key = `/targets/${params.id}/attack`;
  const { data, isLoading } = useSWR<Attack>(key, fetcher, { refreshInterval: 3000 });
  const [busy, setBusy] = useState("");
  const [logRef, setLogRef] = useState<string | null>(null);
  const [openScan, setOpenScan] = useState<number | null>(null);

  async function stop() {
    setBusy("stop");
    try { await api(`/targets/${params.id}/stop`, { method: "POST" }); mutate(key); }
    finally { setBusy(""); }
  }
  async function rerun() {
    setBusy("run");
    try { await api(`/targets/${params.id}/run`, { method: "POST" }); mutate(key); }
    finally { setBusy(""); }
  }

  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [] as Node[], edges: [] as Edge[] };
    const nodes: Node[] = [{
      id: "target", position: { x: 0, y: 80 },
      data: { label: `🎯 ${data.target.value}` },
      style: { background: "#0f2a3a", color: "#e2e8f0", border: "2px solid #22d3ee", borderRadius: 12, padding: 10, width: 230, fontSize: 12 },
      sourcePosition: "right" as any,
    }];
    const assets = data.assets || [];
    (assets.length ? assets : [{ id: "a0", hostname: data.target.value, open_ports: [] }]).forEach((a: any, i: number) => {
      const ports = (a.open_ports || []).map((p: any) => p.port).slice(0, 6).join(", ");
      nodes.push({
        id: `asset-${a.id}`, position: { x: 340, y: i * 110 },
        data: { label: `⬡ ${a.hostname || a.ip}\n${ports ? `ports ${ports}` : "web"}` },
        style: { background: "#16213a", color: "#e2e8f0", border: "2px solid #475569", borderRadius: 12, padding: 10, width: 220, fontSize: 12, whiteSpace: "pre-line" },
        targetPosition: "left" as any,
      });
    });
    const edges: Edge[] = nodes.slice(1).map((n, i) => ({
      id: `e${i}`, source: "target", target: n.id, animated: data.status === "running",
      style: { stroke: "#334155" }, markerEnd: { type: MarkerType.ArrowClosed, color: "#334155" },
    }));
    return { nodes, edges };
  }, [data]);

  if (isLoading || !data) return <div className="p-8"><Spinner /></div>;
  const running = data.status === "running";
  const statusColor = running ? "#f59e0b" : data.status === "stopped" ? "#ef4444" : "#34d399";

  return (
    <div className="p-8">
      <div className="text-xs text-slate-400 mb-3">
        <Link href={`/engagements/${data.engagement_id}`} className="hover:text-accent">{data.engagement_name}</Link>
        {" / "}<span className="text-slate-500">attack #{data.target.id}</span>
      </div>
      <PageHeader title={`${data.target.kind === "app" ? "📦" : "🌐"} ${data.target.value}`}
        subtitle={`${data.client_name} · ${data.engagement_name}`}>
        <span className="chip" style={{ color: statusColor, borderColor: statusColor + "66" }}>
          {running && <span className="inline-block w-2 h-2 rounded-full mr-1.5 animate-pulse" style={{ background: statusColor }} />}
          {data.status}{running ? ` · ${data.active_count} active` : ""}
        </span>
        {running
          ? <button className="btn hover:border-red-500/60 hover:text-red-300" disabled={!!busy} onClick={stop}>■ {busy === "stop" ? "Stopping…" : "Stop attack"}</button>
          : <button className="btn btn-primary" disabled={!!busy} onClick={rerun}>▶ {busy === "run" ? "Starting…" : "Re-run"}</button>}
      </PageHeader>

      {/* status strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        <Stat label="Status" value={data.status} color={statusColor} />
        <Stat label="Started" value={fmtTime(data.started_at)} />
        <Stat label={running ? "Running for" : "Duration"} value={fmtDur(data.duration_s)} />
        <Stat label={running ? "Finished" : "Finished at"} value={running ? "in progress" : fmtTime(data.finished_at)} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">
          {/* timeline */}
          <div className="card p-5">
            <div className="label mb-3">Tools run (this attack) — click for logs</div>
            <div className="space-y-1">
              {data.scans.map((s) => {
                const cont = data.containers.find((c: any) => c.run_id === s.id);
                const isOpen = openScan === s.id;
                return (
                  <div key={s.id}>
                    <button onClick={() => setOpenScan(isOpen ? null : s.id)}
                      className={`w-full flex items-center gap-3 text-sm py-1.5 px-2 rounded-lg ${isOpen ? "bg-panel2" : "hover:bg-panel2"}`}>
                      <span className="font-mono text-accent w-32 truncate text-left">{s.module}</span>
                      <ExecBadge exec={s.execution} />
                      <StatusDot status={s.status} />
                      <span className="w-20 text-slate-300 text-left">{s.status}</span>
                      <span className="text-slate-500 flex-1 text-left truncate">{fmtTime(s.started_at)} → {s.finished_at ? fmtTime(s.finished_at) : "…"}</span>
                      <span className="text-slate-400 font-mono text-xs">{fmtDur(s.duration_s)}</span>
                      <span className="text-slate-500">≡</span>
                    </button>
                    {isOpen && <ScanLogs scanId={s.id} containerRef={cont?.state === "running" ? cont.id : null} />}
                  </div>
                );
              })}
              {!data.scans.length && <div className="text-sm text-slate-400">No tools have run yet.</div>}
            </div>
          </div>

          {/* findings */}
          <div className="card p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="label">Findings ({data.findings.length})</div>
              <div className="w-40"><SevBar counts={data.findings_by_severity} /></div>
            </div>
            <div className="divide-y divide-edge">
              {data.findings.map((f) => (
                <div key={f.id} className="py-2.5">
                  <div className="flex items-center gap-2">
                    <SevBadge sev={f.severity} />
                    <Link href={`/evidence/${f.id}`} className="text-sm hover:text-accent flex-1 truncate">{f.title}</Link>
                    {f.evidence_path && <Link href={`/evidence/${f.id}`} className="chip text-[10px] text-accent border-accent/40">📷</Link>}
                  </div>
                  <div className="mt-1 pl-1"><ControlLinks controls={(f.controls || []) as Control[]} /></div>
                </div>
              ))}
              {!data.findings.length && <div className="text-sm text-slate-400 py-2">No findings yet{running ? " — attack in progress." : "."}</div>}
            </div>
          </div>
        </div>

        <div className="space-y-4">
          {/* attack map */}
          <div className="card p-3">
            <div className="label mb-2 px-2">Attack map</div>
            <div className="h-56 reactflow-wrap rounded-lg overflow-hidden border border-edge">
              <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.3} proOptions={{ hideAttribution: true }} nodesDraggable={false}>
                <Background color="#1e293b" gap={20} />
              </ReactFlow>
            </div>
          </div>

          {/* engaged containers */}
          <div className="card p-5">
            <div className="label mb-2">Engaged images ({data.containers.length})</div>
            <div className="space-y-2">
              {data.containers.map((c) => (
                <div key={c.id} className="rounded-lg border border-edge p-2.5">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${c.state === "running" ? "bg-amber-400 animate-pulse" : "bg-slate-500"}`} />
                    <span className="font-mono text-xs flex-1 truncate">{c.image}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">{c.name} · {c.status}</div>
                  <button className="btn text-[11px] py-0.5 mt-1.5 w-full" onClick={() => setLogRef(logRef === c.id ? null : c.id)}>
                    {logRef === c.id ? "Hide logs" : "≡ Live logs"}
                  </button>
                </div>
              ))}
              {!data.containers.length && <div className="text-xs text-slate-400">{running ? "Spinning up…" : "No live containers — attack finished."}</div>}
            </div>
            {logRef && <div className="mt-2"><Terminal key={logRef} wsPath={`/containers/${logRef}/logs`} readOnly title="live logs" heightClass="h-56" /></div>}
          </div>
        </div>
      </div>
    </div>
  );
}

function ScanLogs({ scanId, containerRef }: { scanId: number; containerRef: string | null }) {
  // Live container logs while running; otherwise the stored tool output.
  const { data } = useSWR<any>(containerRef ? null : `/scans/${scanId}`, fetcher);
  if (containerRef) {
    return <div className="my-2"><Terminal key={`c-${containerRef}`} wsPath={`/containers/${containerRef}/logs`} readOnly title="live container logs" heightClass="h-56" /></div>;
  }
  return (
    <pre className="my-2 bg-ink border border-edge rounded p-2 text-[11px] overflow-auto text-slate-300 max-h-72 whitespace-pre-wrap">
      {data?.raw_output || data?.error || "No output recorded for this tool."}
    </pre>
  );
}

function ExecBadge({ exec }: { exec?: { engine?: string; image?: string | null; label?: string } }) {
  if (!exec?.engine) return null;
  const map: Record<string, { txt: string; cls: string }> = {
    container: { txt: exec.image?.includes("kali") ? "img · kali" : "container", cls: "text-sky-300 border-sky-500/40" },
    "in-process": { txt: "script", cls: "text-slate-400 border-slate-600/50" },
    simulated: { txt: "simulated", cls: "text-amber-300 border-amber-500/40" },
  };
  const m = map[exec.engine] || map["in-process"];
  return <span className={`chip text-[9px] ${m.cls}`} title={exec.label}>{m.txt}</span>;
}
function Stat({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="card p-3">
      <div className="label">{label}</div>
      <div className="text-lg font-semibold mt-0.5 truncate" style={{ color: color || "#fff" }}>{value}</div>
    </div>
  );
}
function StatusDot({ status }: { status: string }) {
  const c = status === "running" ? "#f59e0b" : status === "completed" ? "#34d399" : status === "stopped" ? "#ef4444" : status === "failed" ? "#ef4444" : "#64748b";
  return <span className={`w-2.5 h-2.5 rounded-full ${status === "running" ? "animate-pulse" : ""}`} style={{ background: c }} />;
}

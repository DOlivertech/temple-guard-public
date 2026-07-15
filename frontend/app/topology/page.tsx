"use client";
import { useMemo, useState } from "react";
import useSWR from "swr";
import ReactFlow, { Background, Controls, MarkerType, type Node, type Edge } from "reactflow";
import "reactflow/dist/style.css";
import { fetcher, SEV_COLOR } from "@/lib/api";
import type { Client } from "@/lib/types";
import { PageHeader, Spinner } from "@/components/ui";

const TYPE_STYLE: Record<string, { bg: string; border: string }> = {
  client: { bg: "#1e293b", border: "#38bdf8" },
  engagement: { bg: "#0f2a3a", border: "#22d3ee" },
  asset: { bg: "#16213a", border: "#475569" },
};

export default function TopologyPage() {
  const { data: clients } = useSWR<Client[]>("/clients", fetcher);
  const [client, setClient] = useState<string>("");
  const url = client ? `/topology?client_id=${client}` : "/topology";
  const { data, isLoading } = useSWR<{ nodes: any[]; edges: any[] }>(url, fetcher);

  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [] as Node[], edges: [] as Edge[] };
    const cols: Record<string, number> = { client: 0, engagement: 360, asset: 740 };
    const counters: Record<string, number> = { client: 0, engagement: 0, asset: 0 };
    const nodes: Node[] = data.nodes.map((n) => {
      const idx = counters[n.type]++;
      const style = TYPE_STYLE[n.type] || TYPE_STYLE.asset;
      const borderColor = n.type === "asset" && n.worst_severity ? SEV_COLOR[n.worst_severity] : style.border;
      return {
        id: n.id,
        position: { x: cols[n.type] ?? 0, y: 40 + idx * 110 },
        data: { label: nodeLabel(n) },
        style: {
          background: style.bg, color: "#e2e8f0", border: `2px solid ${borderColor}`,
          borderRadius: 12, padding: 10, width: 250, fontSize: 12, whiteSpace: "pre-line",
          textAlign: "left",
        },
        sourcePosition: "right" as any,
        targetPosition: "left" as any,
      };
    });
    const edges: Edge[] = data.edges.map((e, i) => ({
      id: `e-${i}`, source: e.source, target: e.target,
      animated: true, style: { stroke: "#334155" },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#334155" },
    }));
    return { nodes, edges };
  }, [data]);

  return (
    <div className="p-8 h-screen flex flex-col">
      <PageHeader title="Topology" subtitle="Clients → engagements → discovered assets. Node color = worst finding severity.">
        <select className="input w-56" value={client} onChange={(e) => setClient(e.target.value)}>
          <option value="">All clients</option>
          {(clients || []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </PageHeader>

      <div className="card flex-1 overflow-hidden reactflow-wrap">
        {isLoading ? <Spinner /> : (
          <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.2} proOptions={{ hideAttribution: true }}>
            <Background color="#1e293b" gap={24} />
            <Controls />
          </ReactFlow>
        )}
      </div>
      <div className="flex gap-4 mt-3 text-xs text-slate-400">
        <span className="flex items-center gap-1"><span className="h-3 w-3 rounded border-2" style={{ borderColor: "#38bdf8" }} /> Client</span>
        <span className="flex items-center gap-1"><span className="h-3 w-3 rounded border-2" style={{ borderColor: "#22d3ee" }} /> Engagement</span>
        {["critical", "high", "medium", "low"].map((s) => (
          <span key={s} className="flex items-center gap-1"><span className="h-3 w-3 rounded border-2" style={{ borderColor: SEV_COLOR[s] }} /> {s} asset</span>
        ))}
      </div>
    </div>
  );
}

function nodeLabel(n: any) {
  if (n.type === "client") return `◉ ${n.label}\n${n.status}`;
  if (n.type === "engagement") return `⛨ ${n.label}\n${n.status}`;
  const ports = (n.open_ports || []).map((p: any) => p.port).slice(0, 6).join(", ");
  return `⬡ ${n.label}\n${n.finding_count || 0} findings${ports ? ` · ports ${ports}` : ""}`;
}

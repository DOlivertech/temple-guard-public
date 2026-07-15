"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { api, fetcher } from "@/lib/api";
import type { Engagement } from "@/lib/types";
import { PageHeader, Spinner } from "@/components/ui";

interface Step { module: string; label: string; note: string; params: Record<string, any>; }
interface Playbook { id: string; name: string; description: string; category: string; steps: Step[]; }

const CAT: Record<string, { color: string; label: string }> = {
  recon: { color: "#38bdf8", label: "recon" },
  web: { color: "#34d399", label: "web" },
  network: { color: "#fbbf24", label: "network" },
};

export default function PlaybooksPage() {
  const { data: playbooks } = useSWR<Playbook[]>("/playbooks", fetcher);
  const { data: engs } = useSWR<Engagement[]>("/engagements", fetcher);
  const [launch, setLaunch] = useState<Playbook | null>(null);

  return (
    <div className="p-8">
      <PageHeader title="Playbooks" subtitle="Ordered, multi-step operations run via the Kali container — each step spawns a node you can watch live in the Cluster view">
        <span className="chip text-amber-300 border-amber-500/40">authorized engagements only</span>
      </PageHeader>

      <div className="card p-4 mb-5 border-edge text-sm text-slate-300">
        A playbook chains tools in a fixed order (footprint → scan → discover → vuln-scan).
        Steps run <b>sequentially</b> in Kali containers; launch one and you'll be taken to its live
        attack dashboard, while the <b>Cluster view</b> shows each step's container spin up and down.
      </div>

      {!playbooks ? <Spinner /> : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {playbooks.map((p) => <PlaybookCard key={p.id} pb={p} onRun={() => setLaunch(p)} />)}
        </div>
      )}

      {launch && <LaunchModal pb={launch} engagements={engs || []} onClose={() => setLaunch(null)} />}
    </div>
  );
}

function PlaybookCard({ pb, onRun }: { pb: Playbook; onRun: () => void }) {
  const cat = CAT[pb.category] || { color: "#64748b", label: pb.category };
  return (
    <div className="card p-5 flex flex-col">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="font-semibold text-white">{pb.name}</div>
          <span className="chip text-[10px] mt-1" style={{ color: cat.color, borderColor: cat.color + "66" }}>{cat.label}</span>
        </div>
        <span className="chip text-[10px] text-slate-400">{pb.steps.length} steps</span>
      </div>
      <p className="text-sm text-slate-300 mt-3">{pb.description}</p>

      {/* ordered pipeline */}
      <div className="mt-4 flex flex-wrap items-center gap-1.5">
        {pb.steps.map((s, i) => (
          <div key={i} className="flex items-center gap-1.5">
            <div className="rounded-lg border border-edge bg-panel2 px-2 py-1" title={s.note}>
              <div className="flex items-center gap-1.5">
                <span className="grid place-items-center w-4 h-4 rounded-full bg-accent/20 text-accent text-[9px] font-mono">{i + 1}</span>
                <span className="font-mono text-[11px] text-sky-300">{s.module}</span>
              </div>
              <div className="text-[9px] text-slate-500 mt-0.5 pl-5">{s.label}</div>
            </div>
            {i < pb.steps.length - 1 && <span className="text-slate-600">→</span>}
          </div>
        ))}
      </div>

      <div className="flex-1" />
      <button className="btn btn-primary w-full mt-4" onClick={onRun}>▶ Run playbook</button>
    </div>
  );
}

function LaunchModal({ pb, engagements, onClose }: { pb: Playbook; engagements: Engagement[]; onClose: () => void }) {
  const router = useRouter();
  const [engId, setEngId] = useState(engagements[0]?.id?.toString() || "");
  const [target, setTarget] = useState("");
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const eng = engagements.find((e) => e.id === Number(engId));

  async function go() {
    setBusy(true); setErr("");
    try {
      const r = await api<{ target_id: number }>(`/engagements/${engId}/playbooks/${pb.id}/run`, {
        method: "POST", body: JSON.stringify({ target: target.trim() }),
      });
      router.push(`/attacks/${r.target_id}`);
    } catch (e: any) { setErr(e.message); setBusy(false); }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/60 grid place-items-center p-4" onClick={onClose}>
      <div className="card p-6 max-w-lg w-full" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-lg font-semibold">▦ {pb.name}</h2>
        <p className="text-sm text-slate-300 mt-1">{pb.description}</p>
        <div className="mt-3 space-y-1.5">
          {pb.steps.map((s, i) => (
            <div key={i} className="flex items-start gap-2 text-xs">
              <span className="grid place-items-center w-4 h-4 mt-0.5 rounded-full bg-accent/20 text-accent text-[9px] font-mono shrink-0">{i + 1}</span>
              <div>
                <span className="font-medium text-slate-200">{s.label}</span>
                <span className="font-mono text-[10px] text-sky-300 ml-1.5">{s.module}</span>
                {s.note && <div className="text-[11px] text-slate-400 leading-snug">{s.note}</div>}
              </div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 gap-3 mt-4">
          <div><div className="label mb-1">Engagement (authorization)</div>
            <select className="input" value={engId} onChange={(e) => setEngId(e.target.value)}>
              {engagements.map((e) => <option key={e.id} value={e.id}>{e.name} — {e.client_name}</option>)}
            </select>
            {eng && <div className="text-[11px] text-slate-400 mt-1">ROE: {eng.authorization_ref || "—"}</div>}
          </div>
          <div><div className="label mb-1">Target (host or URL — must be in scope)</div>
            <input className="input font-mono" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://beta.example.com" />
          </div>
        </div>

        <label className="flex items-start gap-2 mt-4 text-sm text-slate-300">
          <input type="checkbox" className="mt-1" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />
          <span>I confirm this target is within the selected engagement's authorized scope and rules-of-engagement window.</span>
        </label>

        {err && <div className="text-sm text-red-400 mt-3">{err}</div>}
        <div className="flex gap-2 mt-5">
          <button className="btn btn-primary" disabled={!confirm || !target.trim() || !engId || busy} onClick={go}>
            {busy ? "Launching…" : `▶ Run ${pb.steps.length}-step pipeline`}
          </button>
          <button className="btn" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

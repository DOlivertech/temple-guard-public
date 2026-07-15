"use client";
import { useState } from "react";
import dynamic from "next/dynamic";
import useSWR, { mutate } from "swr";
import { api, fetcher } from "@/lib/api";
import type { Engagement } from "@/lib/types";
import { PageHeader, Spinner } from "@/components/ui";

const Terminal = dynamic(() => import("@/components/Terminal"), { ssr: false });

interface Instance {
  id: number; engagement_id: number; image: string; ref?: string; status: string;
}

export default function ConsolesPage() {
  const { data: instances, isLoading } = useSWR<Instance[]>("/instances", fetcher, { refreshInterval: 6000 });
  const { data: engs } = useSWR<Engagement[]>("/engagements", fetcher);
  const [engId, setEngId] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [active, setActive] = useState<number | null>(null);

  async function launch() {
    if (!engId) return;
    setBusy(true); setErr("");
    try {
      const inst = await api<Instance>(`/engagements/${engId}/instances`, {
        method: "POST", body: JSON.stringify({}),
      });
      mutate("/instances");
      setActive(inst.id);
    } catch (e: any) { setErr(e.message); }
    finally { setBusy(false); }
  }

  async function stop(id: number) {
    await api(`/instances/${id}/stop`, { method: "POST" });
    if (active === id) setActive(null);
    mutate("/instances");
  }

  const engName = (id: number) => engs?.find((e) => e.id === id)?.name || `eng ${id}`;

  return (
    <div className="p-8">
      <PageHeader title="Kali Consoles" subtitle="Provision Kali instances and shell in — live, from the browser">
        <select className="input w-60" value={engId} onChange={(e) => setEngId(e.target.value)}>
          <option value="">Select engagement…</option>
          {(engs || []).map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
        </select>
        <button className="btn btn-primary" disabled={busy || !engId} onClick={launch}>
          {busy ? "Spinning up…" : "⚡ Launch Kali"}
        </button>
      </PageHeader>

      {err && <div className="text-sm text-red-400 mb-3">{err}</div>}

      {isLoading ? <Spinner /> : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="space-y-2 lg:col-span-1">
            <div className="label mb-1">Instances ({instances?.length || 0})</div>
            {(instances || []).map((i) => (
              <div key={i.id} className={`card p-3 cursor-pointer transition ${active === i.id ? "border-accent" : "hover:border-accent/40"}`} onClick={() => setActive(i.id)}>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm">kali #{i.id}</span>
                  <span className={`chip text-[10px] ${i.status === "running" ? "text-emerald-300 border-emerald-500/40" : "text-slate-400"}`}>● {i.status}</span>
                </div>
                <div className="text-xs text-slate-400 mt-1">{engName(i.engagement_id)}</div>
                <div className="text-[10px] text-slate-500 font-mono mt-0.5">{i.image} {i.ref ? `· ${i.ref}` : ""}</div>
                <div className="flex gap-2 mt-2">
                  <button className="btn text-xs py-1" onClick={(e) => { e.stopPropagation(); setActive(i.id); }}>Open shell</button>
                  <button className="btn text-xs py-1" onClick={(e) => { e.stopPropagation(); stop(i.id); }}>Stop</button>
                </div>
              </div>
            ))}
            {!instances?.length && <div className="text-sm text-slate-400">No instances yet. Launch one above.</div>}
          </div>

          <div className="lg:col-span-2">
            {active ? <Terminal instanceId={active} /> : (
              <div className="card h-96 grid place-items-center text-slate-500 text-sm">
                Select or launch an instance to open a live shell.
              </div>
            )}
            <p className="text-[11px] text-slate-500 mt-2">
              Real shells require Docker (Kali image auto-pulled on first launch). Without Docker you get a simulated console. Cloud-VM / K8s instances are on the roadmap.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

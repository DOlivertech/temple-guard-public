"use client";
import { Suspense, useEffect, useState } from "react";
import useSWR, { mutate } from "swr";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api, fetcher } from "@/lib/api";
import type { Client, Engagement } from "@/lib/types";
import { PageHeader, SevBar, Spinner } from "@/components/ui";
import StandardsPicker from "@/components/StandardsPicker";
import ScopeInput from "@/components/ScopeInput";

export default function EngagementsPage() {
  return (
    <Suspense fallback={<div className="p-8"><Spinner /></div>}>
      <EngagementsInner />
    </Suspense>
  );
}

function EngagementsInner() {
  const params = useSearchParams();
  const clientFilter = params.get("client");
  const listKey = clientFilter ? `/engagements?client_id=${clientFilter}` : "/engagements";

  const { data: engs, isLoading } = useSWR<Engagement[]>(listKey, fetcher);
  const { data: clients } = useSWR<Client[]>("/clients", fetcher);
  const [open, setOpen] = useState(false);

  return (
    <div className="p-8">
      <PageHeader title="Engagements" subtitle="Pick standards, point at an authorized scope, and run the audit">
        <button className="btn btn-primary" onClick={() => setOpen((o) => !o)}>＋ New Engagement</button>
      </PageHeader>

      {open && <NewEngagement clients={clients || []} defaultClient={clientFilter} onDone={() => { setOpen(false); mutate(listKey); }} />}

      {isLoading ? <Spinner /> : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {(engs || []).map((e) => (
            <Link key={e.id} href={`/engagements/${e.id}`} className="card p-5 hover:border-accent/40 transition">
              <div className="flex items-start justify-between">
                <div>
                  <div className="font-semibold text-white">{e.name}</div>
                  <div className="text-xs text-slate-400">{e.client_name} · {e.authorization_ref || "no auth ref"}</div>
                </div>
                <span className="chip text-[10px]">{e.status}</span>
              </div>
              <div className="flex flex-wrap gap-1 mt-3">
                {e.standards.map((s) => <span key={s} className="chip text-[10px] text-accent border-accent/30">{s}</span>)}
              </div>
              <div className="flex items-center gap-2 mt-3 text-xs text-slate-400">
                <span className="font-mono">{e.scope_targets.join(", ")}</span>
              </div>
              <div className="mt-3"><SevBar counts={e.findings_by_severity || {}} /></div>
              <div className="text-xs text-slate-400 mt-2">{e.finding_count ?? 0} findings · provisioner: {e.provisioner}</div>
            </Link>
          ))}
          {!engs?.length && <div className="text-slate-400 text-sm">No engagements yet. Create one to get started.</div>}
        </div>
      )}
    </div>
  );
}

function NewEngagement({ clients, defaultClient, onDone }: {
  clients: Client[]; defaultClient: string | null; onDone: () => void;
}) {
  const [name, setName] = useState("");
  const [clientId, setClientId] = useState(defaultClient || (clients[0]?.id?.toString() ?? ""));
  const [standards, setStandards] = useState<string[]>([]);
  const [scopeTargets, setScopeTargets] = useState<string[]>([]);
  const [authRef, setAuthRef] = useState("");
  const [provisioner, setProvisioner] = useState("docker");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const toggle = (id: string) => setStandards((s) => s.includes(id) ? s.filter((x) => x !== id) : [...s, id]);

  // Auto-fill the authorization reference per client (SOW-YEAR-INITIALS-NNN).
  useEffect(() => {
    if (!clientId) return;
    api<{ auth_ref: string }>(`/clients/${clientId}/next-auth-ref`)
      .then((r) => setAuthRef(r.auth_ref))
      .catch(() => {});
  }, [clientId]);

  async function save() {
    setBusy(true); setErr("");
    try {
      await api("/engagements", {
        method: "POST",
        body: JSON.stringify({
          client_id: Number(clientId),
          name,
          standards,
          scope_targets: scopeTargets,
          authorization_ref: authRef,
          provisioner,
        }),
      });
      onDone();
    } catch (e: any) { setErr(e.message); }
    finally { setBusy(false); }
  }

  return (
    <div className="card p-5 mb-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
        <div><div className="label mb-1">Engagement name</div><input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Q3 External Pentest" /></div>
        <div><div className="label mb-1">Client</div>
          <select className="input" value={clientId} onChange={(e) => setClientId(e.target.value)}>
            {clients.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.authorization_status})</option>)}
          </select>
        </div>
        <div><div className="label mb-1">Authorization reference <span className="text-slate-500 normal-case">(auto · editable)</span></div><input className="input font-mono" value={authRef} onChange={(e) => setAuthRef(e.target.value)} placeholder="SOW-2026-LB-001" /></div>
        <div><div className="label mb-1">Provisioner</div>
          <select className="input" value={provisioner} onChange={(e) => setProvisioner(e.target.value)}>
            <option value="docker">Local Docker (ready)</option>
            <option value="cloud_vm" disabled>Cloud VM — roadmap</option>
            <option value="k8s" disabled>Kubernetes — roadmap</option>
          </select>
        </div>
        <div className="md:col-span-2"><div className="label mb-1">Authorized scope</div>
          <ScopeInput value={scopeTargets} onChange={setScopeTargets} clientId={clientId} />
        </div>
      </div>

      <div className="label mb-2">Select audit standards (single or multiple)</div>
      <StandardsPicker selected={standards} onToggle={toggle} />

      {err && <div className="text-sm text-red-400 mt-3">{err}</div>}
      <div className="flex gap-2 mt-5">
        <button className="btn btn-primary" disabled={busy || !name || !clientId || !standards.length} onClick={save}>
          {busy ? "Creating…" : "Create engagement"}
        </button>
      </div>
    </div>
  );
}

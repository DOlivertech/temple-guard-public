"use client";
import { Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import useSWR from "swr";
import { fetcher } from "@/lib/api";
import type { Client, EvidenceResponse, EvidenceItem } from "@/lib/types";
import { PageHeader, SevBadge, ControlLinks, Spinner } from "@/components/ui";

const SEVS = ["", "critical", "high", "medium", "low", "info"];

export default function EvidencePage() {
  return (
    <Suspense fallback={<div className="p-8"><Spinner /></div>}>
      <EvidenceInner />
    </Suspense>
  );
}

function EvidenceInner() {
  const params = useSearchParams();
  const [client, setClient] = useState(params.get("client") || "");
  const [sev, setSev] = useState("");
  const [shotsOnly, setShotsOnly] = useState(false);
  const [framework, setFramework] = useState("");

  const qs = new URLSearchParams();
  if (client) qs.set("client_id", client);
  if (sev) qs.set("severity", sev);
  if (shotsOnly) qs.set("has_screenshot", "true");
  const { data, isLoading } = useSWR<EvidenceResponse>(`/evidence?${qs}`, fetcher);
  const { data: clients } = useSWR<Client[]>("/clients", fetcher);

  const items = (data?.items || []).filter(
    (i) => !framework || i.controls.some((c) => c.framework === framework));
  const frameworks = Object.keys(data?.by_framework || {}).sort();

  return (
    <div className="p-8">
      <PageHeader title="Evidence" subtitle="Classified findings — what was found, the proof, and the control it violates (linked to source)">
        <Link href="/reports" className="btn">▤ Reports</Link>
      </PageHeader>

      {isLoading || !data ? <Spinner /> : (
        <>
          {/* Summary + filters */}
          <div className="card p-4 mb-5">
            <div className="flex flex-wrap items-center gap-4 mb-3">
              <span className="text-sm"><b className="text-white text-lg">{data.count}</b> <span className="text-slate-400">evidence items</span></span>
              <span className="text-sm"><b className="text-white text-lg">{data.with_screenshots}</b> <span className="text-slate-400">with screenshots</span></span>
              <div className="flex gap-1.5">
                {["critical","high","medium","low","info"].map((s) => data.by_severity[s]
                  ? <span key={s} className="flex items-center gap-1 text-xs"><SevBadge sev={s} /> {data.by_severity[s]}</span> : null)}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <select className="input w-48" value={client} onChange={(e) => setClient(e.target.value)}>
                <option value="">All clients</option>
                {(clients || []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
              <select className="input w-40" value={sev} onChange={(e) => setSev(e.target.value)}>
                {SEVS.map((s) => <option key={s} value={s}>{s ? s : "All severities"}</option>)}
              </select>
              <select className="input w-52" value={framework} onChange={(e) => setFramework(e.target.value)}>
                <option value="">All frameworks</option>
                {frameworks.map((f) => <option key={f} value={f}>{f} ({data.by_framework[f]})</option>)}
              </select>
              <button className={`btn ${shotsOnly ? "btn-primary" : ""}`} onClick={() => setShotsOnly((v) => !v)}>
                {shotsOnly ? "● Screenshots only" : "○ Screenshots only"}
              </button>
            </div>
          </div>

          <div className="space-y-3">
            {items.map((i) => <EvidenceCard key={i.id} item={i} />)}
            {!items.length && <div className="text-sm text-slate-400">No evidence matches these filters.</div>}
          </div>
        </>
      )}
    </div>
  );
}

function EvidenceCard({ item }: { item: EvidenceItem }) {
  return (
    <div id={`ev-${item.id}`} className="card p-4 flex gap-4">
      {item.has_screenshot ? (
        <Link href={`/evidence/${item.id}`} className="shrink-0">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={`/evidence-img/${item.evidence_path}`} alt="evidence"
            className="w-44 h-28 object-cover object-top rounded-lg border border-edge hover:border-accent transition" />
        </Link>
      ) : (
        <div className="shrink-0 w-44 h-28 rounded-lg border border-dashed border-edge grid place-items-center text-[11px] text-slate-500">no screenshot</div>
      )}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <SevBadge sev={item.severity} />
          <Link href={`/evidence/${item.id}`} className="font-medium hover:text-accent truncate">{item.title}</Link>
          {item.cvss ? <span className="chip text-[10px]">CVSS {item.cvss}</span> : null}
          <Link href={`/evidence/${item.id}`} className="ml-auto chip text-[10px] text-slate-400 hover:text-accent" title="Permalink">#{item.id} ↗</Link>
        </div>
        <div className="text-xs text-slate-400 mt-1">
          {item.client_name} · {item.engagement_name}
          {item.module && <> · <span className="font-mono text-accent/80">{item.module}</span></>}
          {item.target && <> · <span className="font-mono">{item.target}</span></>}
        </div>
        {item.description && <p className="text-sm text-slate-300 mt-2 line-clamp-2">{item.description}</p>}
        <div className="mt-2"><ControlLinks controls={item.controls} /></div>
      </div>
    </div>
  );
}

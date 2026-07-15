"use client";
import Link from "next/link";
import useSWR from "swr";
import { fetcher } from "@/lib/api";
import type { EvidenceItem } from "@/lib/types";
import { PageHeader, SevBadge, ControlLinks, Spinner } from "@/components/ui";

export default function EvidenceDetail({ params }: { params: { id: string } }) {
  const { data: item, isLoading, error } = useSWR<EvidenceItem>(`/evidence/${params.id}`, fetcher);

  if (isLoading) return <div className="p-8"><Spinner /></div>;
  if (error || !item) return <div className="p-8 text-slate-400">Evidence item not found. <Link href="/evidence" className="text-accent">← All evidence</Link></div>;

  return (
    <div className="p-8 max-w-5xl">
      <div className="text-xs text-slate-400 mb-3">
        <Link href="/evidence" className="hover:text-accent">Evidence</Link> /
        <Link href={`/engagements/${item.engagement_id}`} className="hover:text-accent"> {item.engagement_name}</Link> /
        <span className="text-slate-500"> #{item.id}</span>
      </div>
      <PageHeader title={item.title} subtitle={`${item.client_name} · ${item.engagement_name}`}>
        <SevBadge sev={item.severity} />
      </PageHeader>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 space-y-4">
          {/* Screenshot proof */}
          {item.has_screenshot && (
            <div className="card p-4">
              <div className="label mb-2">Captured screenshot (Playwright)</div>
              <a href={`/evidence-img/${item.evidence_path}`} target="_blank" rel="noreferrer">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src={`/evidence-img/${item.evidence_path}`} alt="evidence"
                  className="w-full rounded-lg border border-edge hover:border-accent transition" />
              </a>
              <div className="text-[11px] text-slate-500 mt-1">Click to open full-size · {item.evidence_path}</div>
            </div>
          )}

          {/* What was found */}
          <div className="card p-4">
            <div className="label mb-2">What was found</div>
            {item.description && <p className="text-sm text-slate-300">{item.description}</p>}
            {item.evidence && <pre className="bg-ink border border-edge rounded p-2 text-xs overflow-auto text-slate-300 mt-2">{item.evidence}</pre>}
          </div>

          {/* Remediation */}
          {item.remediation && (
            <div className="card p-4">
              <div className="label text-emerald-300 mb-1">Remediation</div>
              <p className="text-sm text-slate-200">{item.remediation}</p>
            </div>
          )}
        </div>

        <div className="space-y-4">
          {/* What it violates — linked controls */}
          <div className="card p-4">
            <div className="label mb-2">What it violates</div>
            {item.controls.length ? (
              <div className="space-y-2">
                {item.controls.map((c, i) => (
                  <a key={i} href={c.url || "#"} target="_blank" rel="noreferrer"
                    className={`block p-2.5 rounded-lg border ${c.url ? "border-edge hover:border-accent bg-panel2" : "border-edge opacity-60"}`}>
                    <div className="flex items-center justify-between">
                      <span className="chip text-[10px] text-accent border-accent/40">{c.framework}</span>
                      {c.url && <span className="text-accent text-xs">open ↗</span>}
                    </div>
                    <div className="text-sm font-medium mt-1">{c.control}</div>
                    <div className="text-xs text-slate-400">{c.title}</div>
                  </a>
                ))}
              </div>
            ) : <div className="text-sm text-slate-400">No mapped controls.</div>}
          </div>

          {/* Metadata */}
          <div className="card p-4 text-sm space-y-2">
            <div className="label mb-1">Details</div>
            <Row k="Severity" v={<SevBadge sev={item.severity} />} />
            {item.cvss != null && <Row k="CVSS" v={String(item.cvss)} />}
            {item.category && <Row k="Category" v={item.category} />}
            {item.module && <Row k="Source tool" v={<span className="font-mono text-accent/80">{item.module}</span>} />}
            {item.standard && <Row k="Suite" v={item.standard} />}
            {item.target && <Row k="Target" v={<span className="font-mono">{item.target}</span>} />}
            <Row k="Status" v={item.status} />
            <Row k="Permalink" v={<Link href={`/evidence/${item.id}`} className="text-[11px] text-accent font-mono hover:underline">/evidence/{item.id}</Link>} />
          </div>
        </div>
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-slate-400 text-xs">{k}</span>
      <span className="text-right">{v}</span>
    </div>
  );
}

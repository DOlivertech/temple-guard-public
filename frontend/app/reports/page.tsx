"use client";
import useSWR from "swr";
import { fetcher } from "@/lib/api";
import type { Engagement } from "@/lib/types";
import { PageHeader, SevBar, Spinner } from "@/components/ui";

export default function ReportsPage() {
  const { data: engs, isLoading } = useSWR<Engagement[]>("/engagements", fetcher);

  return (
    <div className="p-8">
      <PageHeader title="Reports" subtitle="Generate and open client-ready remediation reports per engagement" />
      {isLoading ? <Spinner /> : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {(engs || []).map((e) => (
            <div key={e.id} className="card p-5">
              <div className="flex items-start justify-between">
                <div>
                  <div className="font-semibold text-white">{e.name}</div>
                  <div className="text-xs text-slate-400">{e.client_name} · {e.finding_count ?? 0} findings</div>
                </div>
                <span className="chip text-[10px]">{e.status}</span>
              </div>
              <div className="mt-3"><SevBar counts={e.findings_by_severity || {}} /></div>
              <div className="flex gap-2 mt-4">
                <a className="btn btn-primary" href={`/api/engagements/${e.id}/report`} target="_blank" rel="noreferrer">▤ Open report</a>
                <a className="btn" href={`/api/engagements/${e.id}/report.pdf`}>⬇ Download PDF</a>
              </div>
            </div>
          ))}
        </div>
      )}
      <p className="text-xs text-slate-500 mt-6">Open the report for an interactive view (home, print, and PDF buttons in its header), or download a server-rendered PDF directly. PDF generation runs headless Chromium and may take a few seconds.</p>
    </div>
  );
}

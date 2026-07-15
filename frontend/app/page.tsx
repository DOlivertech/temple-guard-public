"use client";
import useSWR from "swr";
import Link from "next/link";
import { fetcher } from "@/lib/api";
import type { Dashboard, Engagement } from "@/lib/types";
import { PageHeader, StatCard, SevBar, SevBadge, Spinner } from "@/components/ui";

export default function DashboardPage() {
  const { data, isLoading } = useSWR<Dashboard>("/dashboard", fetcher, { refreshInterval: 5000 });
  const { data: engs } = useSWR<Engagement[]>("/engagements", fetcher, { refreshInterval: 5000 });

  return (
    <div className="p-8">
      <PageHeader title="Operations Dashboard" subtitle="Authorized assessments across all clients">
        <Link href="/engagements" className="btn btn-primary">＋ New Audit</Link>
      </PageHeader>

      {isLoading || !data ? <Spinner /> : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
            <StatCard label="Clients" value={data.clients} />
            <StatCard label="Engagements" value={data.engagements} sub={`${data.active_engagements} active`} />
            <StatCard label="Scans Run" value={data.scans} accent="#38bdf8"
              sub={data.scans_running || data.scans_queued
                ? `▶ ${data.scans_running} running · ${data.scans_queued} queued`
                : "idle"} />
            <StatCard label="Findings" value={data.findings} />
            <StatCard label="Open Critical" value={data.open_critical} accent="#ef4444" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="card p-5 lg:col-span-2">
              <div className="label mb-3">Risk distribution (all findings)</div>
              <SevBar counts={data.findings_by_severity} />
              <div className="flex flex-wrap gap-4 mt-4 text-sm">
                {["critical", "high", "medium", "low", "info"].map((s) => (
                  <span key={s} className="flex items-center gap-2">
                    <SevBadge sev={s} /> {data.findings_by_severity[s] || 0}
                  </span>
                ))}
              </div>

              <div className="label mt-6 mb-2">Recent scans</div>
              <div className="space-y-1">
                {data.recent_scans.map((s) => (
                  <div key={s.id} className="flex items-center gap-3 text-sm py-1.5 border-b border-edge/60">
                    <span className="font-mono text-accent w-28 truncate">{s.module}</span>
                    <span className="text-slate-400 flex-1 truncate">{s.target}</span>
                    <span className="chip text-[10px]">{s.standard}</span>
                    <span className="chip text-[10px] text-slate-400">{s.provisioner}</span>
                    <span className={`chip text-[10px] ${s.status === "completed" ? "text-emerald-300 border-emerald-500/40" : "text-amber-300"}`}>{s.status}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="card p-5">
              <div className="label mb-3">Engagements</div>
              <div className="space-y-2">
                {(engs || []).map((e) => (
                  <Link key={e.id} href={`/engagements/${e.id}`} className="block p-3 rounded-lg bg-panel2 hover:border-accent/40 border border-transparent transition">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm">{e.name}</span>
                      <span className="chip text-[10px]">{e.status}</span>
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5">{e.client_name}</div>
                    <div className="mt-2"><SevBar counts={e.findings_by_severity || {}} /></div>
                  </Link>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

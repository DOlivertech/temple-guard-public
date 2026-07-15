"use client";
import { SEV_COLOR } from "@/lib/api";

export function PageHeader({ title, subtitle, children }: {
  title: string; subtitle?: string; children?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 mb-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">{title}</h1>
        {subtitle && <p className="text-sm text-slate-400 mt-1">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-2">{children}</div>
    </div>
  );
}

export function SevBadge({ sev }: { sev: string }) {
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wide text-white"
      style={{ background: SEV_COLOR[sev] || "#64748b" }}
    >
      {sev}
    </span>
  );
}

export function SevBar({ counts }: { counts: Record<string, number> }) {
  const order = ["critical", "high", "medium", "low", "info"];
  const total = order.reduce((a, s) => a + (counts[s] || 0), 0) || 1;
  return (
    <div className="flex h-2 w-full overflow-hidden rounded-full bg-edge">
      {order.map((s) =>
        counts[s] ? (
          <div key={s} style={{ width: `${(counts[s] / total) * 100}%`, background: SEV_COLOR[s] }} title={`${s}: ${counts[s]}`} />
        ) : null
      )}
    </div>
  );
}

export function StatCard({ label, value, accent, sub }: {
  label: string; value: React.ReactNode; accent?: string; sub?: string;
}) {
  return (
    <div className="card p-4">
      <div className="label">{label}</div>
      <div className="text-3xl font-semibold mt-1" style={{ color: accent || "#fff" }}>{value}</div>
      {sub && <div className="text-xs text-slate-400 mt-1">{sub}</div>}
    </div>
  );
}

export function AuthBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    authorized: "text-emerald-300 border-emerald-500/40",
    pending: "text-amber-300 border-amber-500/40",
    revoked: "text-red-300 border-red-500/40",
  };
  return <span className={`chip ${map[status] || ""}`}>● {status}</span>;
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return <div className="text-sm text-slate-400 animate-pulse p-8">{label}</div>;
}

interface Control { ref: string; framework: string; control: string; title?: string; url: string | null; }

export function ControlLinks({ controls, label = "Violates" }: { controls: Control[]; label?: string }) {
  if (!controls?.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="label">{label}:</span>
      {controls.map((c, i) =>
        c.url ? (
          <a key={i} href={c.url} target="_blank" rel="noreferrer"
            title={`${c.title || c.framework} ${c.control} — open authoritative source`}
            className="chip text-[10px] text-accent border-accent/40 hover:bg-accent/15 hover:underline">
            {c.framework} {c.control} ↗
          </a>
        ) : (
          <span key={i} className="chip text-[10px] text-slate-400">{c.ref}</span>
        )
      )}
    </div>
  );
}

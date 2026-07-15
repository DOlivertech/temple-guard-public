"use client";
import useSWR from "swr";
import { fetcher } from "@/lib/api";
import type { Standard } from "@/lib/types";

const CAT_LABEL: Record<string, string> = {
  web: "Web Application", network: "Network / Infra", config: "Config Hardening",
  compliance: "Regulatory / Compliance", app: "Application / Binary", redteam: "Red Team",
};
const CAT_ORDER = ["web", "network", "config", "compliance", "app", "redteam"];

export default function StandardsPicker({ selected, onToggle }: {
  selected: string[];
  onToggle: (id: string) => void;
}) {
  const { data } = useSWR<Standard[]>("/standards", fetcher);
  if (!data) return <div className="text-sm text-slate-400">Loading suites…</div>;

  const byCat = CAT_ORDER.map((cat) => ({ cat, items: data.filter((s) => s.category === cat) }))
    .filter((g) => g.items.length);

  return (
    <div className="space-y-5">
      {byCat.map((g) => (
        <div key={g.cat}>
          <div className="label mb-2">{CAT_LABEL[g.cat] || g.cat}</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {g.items.map((s) => {
              const on = selected.includes(s.id);
              const disabled = !s.available;
              return (
                <button
                  key={s.id}
                  type="button"
                  disabled={disabled}
                  onClick={() => onToggle(s.id)}
                  className={`text-left p-3 rounded-lg border transition ${
                    disabled ? "opacity-50 cursor-not-allowed border-edge bg-panel2"
                      : on ? "border-accent bg-accent/15"
                      : "border-edge bg-panel2 hover:border-accent/50"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-sm">{s.name}</span>
                    <span className={`h-4 w-4 shrink-0 rounded grid place-items-center text-[10px] ${on ? "bg-accent text-ink" : "border border-edge"}`}>{on ? "✓" : ""}</span>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="chip text-[9px] text-accent border-accent/30">{s.framework}</span>
                    {disabled && <span className="chip text-[9px] text-amber-300 border-amber-500/40">roadmap</span>}
                  </div>
                  <p className="text-xs text-slate-400 mt-2 leading-snug">{s.description}</p>
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

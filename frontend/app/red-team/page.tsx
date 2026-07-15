"use client";
import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { api, fetcher } from "@/lib/api";
import type { Engagement } from "@/lib/types";
import { PageHeader, Spinner } from "@/components/ui";

interface Op {
  id: string; name: string; team: string; category: string;
  attack: string; attack_url: string; aggressiveness: string; executable: boolean;
  engine: "in-process" | "kali" | "simulated";
  summary: string; explanation: string; hardening: string; warning: string; refusal?: string;
}

const TEAMS = [
  { id: "red", label: "Red", color: "#ef4444", blurb: "Adversary emulation — offensive operations (executable ones are bounded & non-destructive)." },
  { id: "purple", label: "Purple", color: "#a855f7", blurb: "Collaborative — run safe tests, verify detections fire." },
  { id: "blue", label: "Blue", color: "#3b82f6", blurb: "Defensive posture validation, non-intrusive." },
  { id: "soc", label: "SOC", color: "#14b8a6", blurb: "Detection & response readiness — emit benign signals, confirm alerting." },
];
const ENGINE_CHIP: Record<string, { txt: string; cls: string }> = {
  "in-process": { txt: "script", cls: "text-slate-400 border-slate-600/50" },
  kali: { txt: "img · kali", cls: "text-sky-300 border-sky-500/40" },
  simulated: { txt: "simulated", cls: "text-amber-300 border-amber-500/40" },
};
const CRED_OPS = ["cred_spray", "detection_replay", "user_enumeration"];
const AGG_COLOR: Record<string, string> = {
  passive: "#64748b", low: "#3b82f6", moderate: "#eab308", aggressive: "#f97316", destructive: "#ef4444",
};

export default function RedTeamPage() {
  const { data: ops } = useSWR<Op[]>("/redteam/operations", fetcher);
  const { data: engs } = useSWR<Engagement[]>("/engagements", fetcher);
  const [team, setTeam] = useState("red");
  const [launch, setLaunch] = useState<Op | null>(null);

  const filtered = useMemo(() => (ops || []).filter((o) => o.team === team), [ops, team]);
  const teamMeta = TEAMS.find((t) => t.id === team)!;

  return (
    <div className="p-8">
      <PageHeader title="Team Operations" subtitle="Red · Purple · Blue · SOC — adversary emulation, detection validation, and defensive checks">
        <span className="chip text-amber-300 border-amber-500/40">authorized engagements only</span>
      </PageHeader>

      <div className="card p-4 mb-5 border-amber-500/30">
        <p className="text-sm text-slate-300">
          <b className="text-amber-300">⚠ Authorization required.</b> Operations only run against an
          authorized engagement, within its rules-of-engagement window, after explicit confirmation.
          Executable checks are <b>bounded and non-destructive</b> (recon, posture, CORS/method/cookie
          audits, a hard-capped resilience probe, and a capped credential-lockout test that uses
          fake passwords). Offensive techniques (high-volume brute-force, exploitation, web-shell,
          flooding DoS, phishing, lateral movement, exfiltration) are <b>documented and simulated
          only</b> — Temple Guard will not execute them. The <span className="font-mono text-[11px]">script</span> /
          <span className="font-mono text-[11px]"> img·kali</span> chip shows where each op runs.
        </p>
      </div>

      <div className="flex gap-2 mb-1">
        {TEAMS.map((t) => (
          <button key={t.id} onClick={() => setTeam(t.id)}
            className={`btn ${team === t.id ? "btn-primary" : ""}`}
            style={team === t.id ? { background: t.color, borderColor: t.color, color: "#0b1120" } : {}}>
            {t.label} Team
          </button>
        ))}
      </div>
      <p className="text-xs text-slate-400 mb-4">{teamMeta.blurb}</p>

      {!ops ? <Spinner /> : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filtered.map((o) => <OpCard key={o.id} op={o} onLaunch={() => setLaunch(o)} />)}
        </div>
      )}

      {launch && <LaunchModal op={launch} engagements={engs || []} onClose={() => setLaunch(null)} />}
    </div>
  );
}

function OpCard({ op, onLaunch }: { op: Op; onLaunch: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="card p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="font-semibold text-white">{op.name}</div>
          <a href={op.attack_url} target="_blank" rel="noreferrer" className="text-xs text-accent hover:underline">{op.attack} ↗</a>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span className="chip text-[10px] text-white" style={{ background: AGG_COLOR[op.aggressiveness] }}>{op.aggressiveness}</span>
          <span className={`chip text-[10px] ${op.executable ? "text-emerald-300 border-emerald-500/40" : "text-slate-400"}`}>{op.executable ? "executable" : "won't execute"}</span>
          <span className={`chip text-[9px] ${ENGINE_CHIP[op.engine]?.cls}`} title={op.engine === "kali" ? "Runs a real tool inside templeguard/kali" : op.engine === "in-process" ? "Bounded in-process script (no container)" : "Documented only — not executed"}>{ENGINE_CHIP[op.engine]?.txt}</span>
        </div>
      </div>
      <p className="text-sm text-slate-300 mt-3">{op.summary}</p>
      <button className="text-[11px] text-accent hover:underline mt-2" onClick={() => setOpen((v) => !v)}>{open ? "Hide details" : "What will be done? ▾"}</button>
      {open && (
        <div className="mt-2 space-y-2 text-xs">
          <div><div className="label">Explanation</div><p className="text-slate-300">{op.explanation}</p></div>
          {op.refusal && <div className="rounded-lg bg-red-500/10 border border-red-500/30 p-2 text-red-200"><div className="label text-red-300">Why we won't execute it</div>{op.refusal}</div>}
          <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/30 p-2"><div className="label text-emerald-300">Hardening</div><p className="text-slate-200">{op.hardening}</p></div>
          <div className="rounded-lg bg-amber-500/10 border border-amber-500/30 p-2 text-amber-200">⚠ {op.warning}</div>
        </div>
      )}
      <button className="btn w-full mt-3" onClick={onLaunch}
        style={op.aggressiveness === "destructive" ? { borderColor: "#ef444466" } : {}}>
        {op.executable ? "▶ Launch operation" : "▶ Assess (simulated)"}
      </button>
    </div>
  );
}

function LaunchModal({ op, engagements, onClose }: { op: Op; engagements: Engagement[]; onClose: () => void }) {
  const router = useRouter();
  const [engId, setEngId] = useState(engagements[0]?.id?.toString() || "");
  const [target, setTarget] = useState("");
  const [loginUrl, setLoginUrl] = useState("");
  const [usernames, setUsernames] = useState("");
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const eng = engagements.find((e) => e.id === Number(engId));
  const isCred = CRED_OPS.includes(op.id);

  async function go() {
    setBusy(true); setErr("");
    try {
      const extra: Record<string, any> = {};
      if (isCred) {
        if (loginUrl.trim()) extra.login_url = loginUrl.trim();
        const us = usernames.split(",").map((u) => u.trim()).filter(Boolean);
        if (us.length) extra.usernames = us;
      }
      const t = await api<{ id: number }>(`/engagements/${engId}/targets`, {
        method: "POST", body: JSON.stringify({
          kind: "redteam", value: target.trim(), operation: op.id, team: op.team,
          extra, label: `${op.name} · ${target.trim()}` }) });
      await api(`/targets/${t.id}/run`, { method: "POST" });
      router.push(`/attacks/${t.id}`);
    } catch (e: any) { setErr(e.message); setBusy(false); }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/60 grid place-items-center p-4" onClick={onClose}>
      <div className="card p-6 max-w-lg w-full" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-1">
          <span className="chip text-[10px] text-white" style={{ background: AGG_COLOR[op.aggressiveness] }}>{op.aggressiveness}</span>
          <h2 className="text-lg font-semibold">{op.name}</h2>
        </div>
        <a href={op.attack_url} target="_blank" rel="noreferrer" className="text-xs text-accent hover:underline">{op.attack} ↗</a>

        <div className="mt-3 text-sm text-slate-300">{op.explanation}</div>
        <div className="mt-3 rounded-lg bg-amber-500/10 border border-amber-500/40 p-3 text-amber-200 text-sm">⚠ {op.warning}</div>

        <div className="grid grid-cols-1 gap-3 mt-4">
          <div><div className="label mb-1">Engagement (authorization)</div>
            <select className="input" value={engId} onChange={(e) => setEngId(e.target.value)}>
              {engagements.map((e) => <option key={e.id} value={e.id}>{e.name} — {e.client_name}</option>)}
            </select>
            {eng && <div className="text-[11px] text-slate-400 mt-1">ROE window: {eng.authorization_ref || "—"}</div>}
          </div>
          <div><div className="label mb-1">Target (host or URL)</div>
            <input className="input font-mono" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="beta.example.com" />
          </div>
          {isCred && (
            <div className="rounded-lg border border-edge bg-panel2 p-3 space-y-2">
              <div className="text-[11px] text-slate-400">Credential-control test — uses <b>fake passwords only</b>, hard-capped. Optionally point it at the login endpoint and the account(s) you own.</div>
              <div><div className="label mb-1">Login URL (optional — auto-discovered if blank)</div>
                <input className="input font-mono text-xs" value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)} placeholder="https://beta.example.com/api/login" />
              </div>
              <div><div className="label mb-1">Username(s) you authorize (comma-separated)</div>
                <input className="input font-mono text-xs" value={usernames} onChange={(e) => setUsernames(e.target.value)} placeholder="admin@yourco.com" />
              </div>
            </div>
          )}
        </div>

        <label className="flex items-start gap-2 mt-4 text-sm text-slate-300">
          <input type="checkbox" className="mt-1" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />
          <span>I confirm this target is within the selected engagement's authorized scope and rules-of-engagement window, and I am permitted to run this operation.</span>
        </label>

        {err && <div className="text-sm text-red-400 mt-3">{err}</div>}
        <div className="flex gap-2 mt-5">
          <button className="btn btn-primary" disabled={!confirm || !target.trim() || !engId || busy}
            style={op.aggressiveness === "destructive" || op.aggressiveness === "aggressive" ? { background: "#ef4444", borderColor: "#ef4444" } : {}}
            onClick={go}>{busy ? "Launching…" : op.executable ? "▶ Execute operation" : "▶ Run simulation"}</button>
          <button className="btn" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

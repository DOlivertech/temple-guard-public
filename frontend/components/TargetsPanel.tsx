"use client";
import { useState } from "react";
import Link from "next/link";
import useSWR, { mutate } from "swr";
import { api, fetcher } from "@/lib/api";
import type { AuditTarget } from "@/lib/types";

const OSES = ["linux", "windows", "macos"];

export default function TargetsPanel({ engagementId }: { engagementId: number }) {
  const key = `/engagements/${engagementId}/targets`;
  const { data: targets } = useSWR<AuditTarget[]>(key, fetcher, { refreshInterval: 4000 });
  const [kind, setKind] = useState<"web" | "app" | "api" | "phone">("web");
  const [value, setValue] = useState("");
  const [os, setOs] = useState("linux");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  async function add() {
    if (!value.trim()) return;
    setBusy(true); setMsg("");
    try {
      await api(key, { method: "POST", body: JSON.stringify({
        kind, value: value.trim(), os: kind === "app" ? os : null, label: label.trim() || null }) });
      setValue(""); setLabel("");
      mutate(key);
    } catch (e: any) { setMsg(e.message); }
    finally { setBusy(false); }
  }

  async function run(t: AuditTarget) {
    setMsg("");
    try {
      const r = await api(`/targets/${t.id}/run`, { method: "POST" });
      setMsg(`▶ Spun up — queued ${r.queued} tool(s) against ${t.kind} target.`);
      mutate(key);
    } catch (e: any) { setMsg(`✗ ${e.message}`); }
  }

  async function stop(t: AuditTarget) {
    setMsg("");
    try {
      const r = await api(`/targets/${t.id}/stop`, { method: "POST" });
      setMsg(`■ Stopped — killed ${r.containers_killed} container(s).`);
      mutate(key);
    } catch (e: any) { setMsg(`✗ ${e.message}`); }
  }

  async function del(t: AuditTarget) {
    if (t.last_status === "running" &&
        !confirm("This target's attack is still running. Deleting it will stop the test and kill its containers. Continue?")) return;
    await api(`/targets/${t.id}`, { method: "DELETE" });
    mutate(key);
  }

  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="label">Audit targets</div>
        <span className="text-[10px] text-slate-500">container spins up to attack each</span>
      </div>

      {/* Add form */}
      <div className="bg-panel2 rounded-lg p-3 mb-3">
        <div className="flex gap-1 mb-2">
          <button onClick={() => setKind("web")}
            className={`btn text-xs py-1 flex-1 ${kind === "web" ? "btn-primary" : ""}`}>🌐 Web</button>
          <button onClick={() => setKind("api")}
            className={`btn text-xs py-1 flex-1 ${kind === "api" ? "btn-primary" : ""}`}>◎ API</button>
          <button onClick={() => setKind("phone")}
            className={`btn text-xs py-1 flex-1 ${kind === "phone" ? "btn-primary" : ""}`}>☎ Phone</button>
          <button onClick={() => setKind("app")}
            className={`btn text-xs py-1 flex-1 ${kind === "app" ? "btn-primary" : ""}`}>📦 App</button>
        </div>
        <input className="input text-sm mb-2 font-mono" value={value} onChange={(e) => setValue(e.target.value)}
          placeholder={kind === "web" ? "https://app.example.com" : kind === "api" ? "https://api.example.com" : kind === "phone" ? "+1 415 555 0100" : "/path/to/app  or  https://.../installer.dmg"} />
        {kind === "phone" && (
          <p className="text-[10px] text-slate-500 mb-2 leading-snug">
            Phone-number OSINT (PhoneInfoga) — country, line type, and the public footprint
            an attacker could pivot on. Only assess numbers your engagement authorizes.
          </p>
        )}
        {kind === "app" && (
          <div className="flex items-center gap-2 mb-2">
            <span className="label">Target OS</span>
            <select className="input text-sm w-36" value={os} onChange={(e) => setOs(e.target.value)}>
              {OSES.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
          </div>
        )}
        <input className="input text-sm mb-2" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="label (optional)" />
        <button className="btn btn-primary text-xs w-full" disabled={busy || !value.trim()} onClick={add}>
          {busy ? "Adding…" : "＋ Add target"}
        </button>
        {kind === "app" && (
          <p className="text-[10px] text-slate-500 mt-2 leading-snug">
            Container downloads/mounts the artifact and statically dissects it (secrets,
            endpoints, signing, bundled deps). Live detonation is Linux-only / roadmap.
          </p>
        )}
      </div>

      {msg && <div className="text-xs text-slate-300 mb-2">{msg}</div>}

      {/* Target list */}
      <div className="space-y-2">
        {(targets || []).map((t) => (
          <div key={t.id} className="rounded-lg border border-edge p-2.5">
            <div className="flex items-center gap-2">
              <span className="text-sm">{t.kind === "web" ? "🌐" : t.kind === "api" ? "◎" : t.kind === "phone" ? "☎" : "📦"}</span>
              <span className="font-mono text-xs flex-1 truncate" title={t.value}>{t.label || t.value}</span>
              {t.os && <span className="chip text-[9px]">{t.os}</span>}
              <span className={`chip text-[9px] ${t.last_status === "running" ? "text-amber-300 border-amber-500/40" : t.last_status === "completed" ? "text-emerald-300 border-emerald-500/40" : "text-slate-400"}`}>{t.last_status || "idle"}</span>
            </div>
            <div className="flex gap-1.5 mt-2">
              {t.kind === "api"
                ? <Link href={`/api-test/${t.id}`} className="btn text-[11px] py-0.5 flex-1">◎ API tester →</Link>
                : t.last_status === "running"
                  ? <button className="btn text-[11px] py-0.5 flex-1 hover:border-red-500/60 hover:text-red-300" onClick={() => stop(t)}>■ Stop attack</button>
                  : <button className="btn text-[11px] py-0.5 flex-1" onClick={() => run(t)}>▶ Spin up &amp; attack</button>}
              <Link href={`/attacks/${t.id}`} className="btn text-[11px] py-0.5">Dashboard →</Link>
              <button className="btn text-[11px] py-0.5" onClick={() => del(t)}>✕</button>
            </div>
          </div>
        ))}
        {!targets?.length && <div className="text-xs text-slate-400">No targets yet. Add a web address or an app above.</div>}
      </div>
    </div>
  );
}

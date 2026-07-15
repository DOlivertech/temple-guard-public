"use client";
import { useState } from "react";
import useSWR, { mutate } from "swr";
import { api, fetcher, SEV_ORDER } from "@/lib/api";
import type { Finding } from "@/lib/types";
import Link from "next/link";
import { PageHeader, SevBadge, SevBar, Spinner, ControlLinks } from "@/components/ui";
import StandardsPicker from "@/components/StandardsPicker";
import TargetsPanel from "@/components/TargetsPanel";
import ScopeInput from "@/components/ScopeInput";

export default function EngagementDetail({ params }: { params: { id: string } }) {
  const key = `/engagements/${params.id}`;
  const { data, isLoading } = useSWR<any>(key, fetcher, { refreshInterval: 4000 });
  const [selected, setSelected] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [msg, setMsg] = useState("");
  const [openFinding, setOpenFinding] = useState<number | null>(null);
  const [editScope, setEditScope] = useState(false);
  const [scopeDraft, setScopeDraft] = useState<string[]>([]);
  const [netDraft, setNetDraft] = useState("");
  const [editNet, setEditNet] = useState(false);

  const toggle = (id: string) => setSelected((s) => s.includes(id) ? s.filter((x) => x !== id) : [...s, id]);

  async function saveScope() {
    await api(`/engagements/${params.id}`, { method: "PATCH", body: JSON.stringify({ scope_targets: scopeDraft }) });
    setEditScope(false);
    mutate(key);
  }

  async function saveNet(v: string) {
    await api(`/engagements/${params.id}`, { method: "PATCH", body: JSON.stringify({ scan_network: v.trim() || "bridge" }) });
    setEditNet(false);
    mutate(key);
  }

  async function run() {
    setRunning(true); setMsg("");
    try {
      const std = selected.length ? selected : data.standards;
      const res = await api(`/engagements/${params.id}/run`, {
        method: "POST", body: JSON.stringify({ standards: std }),
      });
      setMsg(`✓ Queued ${res.queued} scan(s) — running in background.`);
      mutate(key);
    } catch (e: any) { setMsg(`✗ ${e.message}`); }
    finally { setRunning(false); }
  }

  async function genReport() {
    await api(`/engagements/${params.id}/report`, { method: "POST" });
    window.open(`/api/engagements/${params.id}/report`, "_blank");
  }

  async function setStatus(f: Finding, status: string) {
    await api(`/findings/${f.id}`, { method: "PATCH", body: JSON.stringify({ status }) });
    mutate(key);
  }

  if (isLoading || !data) return <div className="p-8"><Spinner /></div>;
  const findings: Finding[] = [...(data.findings || [])].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || (b.cvss || 0) - (a.cvss || 0));

  return (
    <div className="p-8">
      <PageHeader title={data.name} subtitle={`${data.client_name} · ${data.authorization_ref || "no auth ref"} · provisioner: ${data.provisioner}`}>
        <button className="btn" onClick={genReport}>▤ Report</button>
        <a className="btn" href={`/api/engagements/${params.id}/report.pdf`}>⬇ PDF</a>
        <button className="btn btn-primary" disabled={running} onClick={run}>{running ? "Running…" : "▶ Run Audit"}</button>
      </PageHeader>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">
          <div className="card p-5">
            <div className="flex items-center justify-between mb-2">
              <div className="label">Select standards to run {selected.length ? `(${selected.length} selected)` : "(defaults to saved suites)"}</div>
              {msg && <span className="text-xs text-slate-300">{msg}</span>}
            </div>
            <div className="flex flex-wrap gap-1 mb-4">
              {data.standards.map((s: string) => <span key={s} className="chip text-[10px] text-accent border-accent/30">{s}</span>)}
            </div>
            <StandardsPicker selected={selected} onToggle={toggle} />
          </div>

          <div className="card p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="label">Findings ({findings.length})</div>
              <div className="w-40"><SevBar counts={data.findings_by_severity || {}} /></div>
            </div>
            <div className="divide-y divide-edge">
              {findings.map((f) => (
                <div key={f.id} className="py-3">
                  <button className="w-full text-left flex items-center gap-3" onClick={() => setOpenFinding(openFinding === f.id ? null : f.id)}>
                    <SevBadge sev={f.severity} />
                    <span className="flex-1 text-sm font-medium">{f.title}</span>
                    {f.cvss && <span className="chip text-[10px]">CVSS {f.cvss}</span>}
                    <span className={`chip text-[10px] ${f.status === "open" ? "text-slate-300" : "text-emerald-300 border-emerald-500/40"}`}>{f.status}</span>
                    <span className="text-slate-500">{openFinding === f.id ? "▲" : "▼"}</span>
                  </button>
                  {openFinding === f.id && (
                    <div className="mt-3 pl-2 border-l-2 border-edge ml-1 space-y-3 text-sm">
                      {(f as any).controls?.length > 0
                        ? <ControlLinks controls={(f as any).controls} />
                        : f.standard_refs?.length > 0 && (
                          <div className="flex flex-wrap gap-1">{f.standard_refs.map((r) => <span key={r} className="chip text-[10px]">{r}</span>)}</div>
                        )}
                      {f.description && <p className="text-slate-300">{f.description}</p>}
                      {f.evidence && <pre className="bg-ink border border-edge rounded p-2 text-xs overflow-auto text-slate-300">{f.evidence}</pre>}
                      {f.evidence_path && (
                        <div>
                          <div className="label mb-1">Captured screenshot (Playwright)</div>
                          <a href={`/evidence-img/${f.evidence_path}`} target="_blank" rel="noreferrer">
                            <img src={`/evidence-img/${f.evidence_path}`} alt="evidence"
                              className="rounded-lg border border-edge max-h-72 hover:border-accent transition" />
                          </a>
                        </div>
                      )}
                      <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/30 p-3">
                        <div className="label text-emerald-300 mb-1">Remediation</div>
                        <p className="text-slate-200">{f.remediation}</p>
                      </div>
                      <div className="flex gap-2">
                        <button className="btn text-xs py-1" onClick={() => setStatus(f, "remediated")}>Mark remediated</button>
                        <button className="btn text-xs py-1" onClick={() => setStatus(f, "accepted_risk")}>Accept risk</button>
                        <button className="btn text-xs py-1" onClick={() => setStatus(f, "false_positive")}>False positive</button>
                        <Link href={`/evidence/${f.id}`} className="btn text-xs py-1 ml-auto">▣ View evidence →</Link>
                      </div>
                    </div>
                  )}
                </div>
              ))}
              {!findings.length && <div className="text-sm text-slate-400 py-4">No findings yet — run an audit above.</div>}
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <TargetsPanel engagementId={Number(params.id)} />
          <div className="card p-5">
            <div className="flex items-center justify-between mb-2">
              <div className="label">Authorized scope</div>
              {!editScope
                ? <button className="text-[11px] text-accent hover:underline" onClick={() => { setScopeDraft(data.scope_targets || []); setEditScope(true); }}>✎ edit</button>
                : <span className="text-[11px] text-slate-500">editing</span>}
            </div>
            {!editScope ? (
              <div className="space-y-1">
                {data.scope_targets.map((t: string) => (
                  <div key={t} className="font-mono text-sm flex items-center gap-2">
                    <span className={t === "*" ? "text-amber-400" : "text-emerald-400"}>●</span>{t === "*" ? "any target (✶)" : t}
                  </div>
                ))}
                {!data.scope_targets?.length && <div className="text-xs text-slate-400">No scope set.</div>}
              </div>
            ) : (
              <div>
                <ScopeInput value={scopeDraft} onChange={setScopeDraft} clientId={data.client_id} />
                <div className="flex gap-2 mt-2">
                  <button className="btn btn-primary text-xs py-1" onClick={saveScope}>Save scope</button>
                  <button className="btn text-xs py-1" onClick={() => setEditScope(false)}>Cancel</button>
                </div>
              </div>
            )}
          </div>
          <div className="card p-5">
            <div className="flex items-center justify-between mb-2">
              <div className="label">Scan network</div>
              {!editNet
                ? <button className="text-[11px] text-accent hover:underline" onClick={() => { setNetDraft(data.scan_network || "bridge"); setEditNet(true); }}>✎ edit</button>
                : <span className="text-[11px] text-slate-500">editing</span>}
            </div>
            {!editNet ? (
              <div>
                <span className="font-mono text-sm">{data.scan_network || "bridge"}</span>
                {(data.scan_network && data.scan_network !== "bridge") &&
                  <span className="chip text-[9px] ml-2 text-amber-300 border-amber-500/40">inherits host/VPN routes</span>}
                <p className="text-[11px] text-slate-500 mt-2 leading-snug">
                  Docker network for this engagement's scan containers. Use <b>host</b> (Linux engine) or a
                  <b> container:&lt;vpn&gt;</b> sidecar to reach a client's private network you have VPN access to.
                </p>
              </div>
            ) : (
              <div>
                <div className="flex gap-1.5 mb-2">
                  {["bridge", "host"].map((p) => (
                    <button key={p} onClick={() => setNetDraft(p)}
                      className={`btn text-xs py-1 flex-1 ${netDraft === p ? "btn-primary" : ""}`}>{p}</button>
                  ))}
                </div>
                <input className="input text-sm font-mono mb-2" value={netDraft} onChange={(e) => setNetDraft(e.target.value)}
                  placeholder="bridge | host | container:vpn | my-net" />
                <div className="flex gap-2">
                  <button className="btn btn-primary text-xs py-1" onClick={() => saveNet(netDraft)}>Save</button>
                  <button className="btn text-xs py-1" onClick={() => setEditNet(false)}>Cancel</button>
                </div>
                <p className="text-[10px] text-slate-500 mt-2 leading-snug">
                  ⚠ <b>host</b> shares the engine host's network namespace (incl. a VPN tunnel) — Linux only.
                  On macOS Docker Desktop the Mac's VPN isn't in the Docker VM; use a VPN sidecar
                  (<span className="font-mono">container:&lt;name&gt;</span>) or run the engine on a Linux host on the VPN.
                  <br/>Sidecar (OpenVPN/WireGuard/Tailscale): <span className="font-mono">scripts/vpn-sidecar.sh up …</span> → set <span className="font-mono">container:tg-vpn</span>.
                </p>
              </div>
            )}
          </div>
          <div className="card p-5">
            <div className="label mb-2">Discovered assets ({data.assets?.length || 0})</div>
            <div className="space-y-2">
              {(data.assets || []).map((a: any) => (
                <div key={a.id} className="bg-panel2 rounded-lg p-3">
                  <div className="font-mono text-sm">{a.hostname || a.ip}</div>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {(a.open_ports || []).map((p: any) => (
                      <span key={p.port} className="chip text-[10px]">{p.port}/{p.service}</span>
                    ))}
                  </div>
                </div>
              ))}
              {!data.assets?.length && <div className="text-xs text-slate-400">No assets discovered yet.</div>}
            </div>
          </div>
          <div className="card p-5">
            <div className="label mb-2">Scan history ({data.scans?.length || 0})</div>
            <div className="space-y-1 max-h-64 overflow-auto">
              {(data.scans || []).slice().reverse().map((s: any) => (
                <div key={s.id} className="text-xs flex items-center gap-2 py-1">
                  <span className="font-mono text-accent">{s.module}</span>
                  <span className="text-slate-500 flex-1 truncate">{s.standard}</span>
                  <span className={s.status === "completed" ? "text-emerald-400" : "text-amber-400"}>{s.status}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

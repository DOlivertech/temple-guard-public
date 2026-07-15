"use client";
import { useMemo, useState } from "react";
import dynamic from "next/dynamic";
import useSWR, { mutate } from "swr";
import { api, fetcher } from "@/lib/api";
import { PageHeader, Spinner } from "@/components/ui";
import ClusterView from "@/components/ClusterView";

const Terminal = dynamic(() => import("@/components/Terminal"), { ssr: false });

interface Container {
  id: string; name: string; image: string; state: string; status: string;
  created: string; role: string; managed?: boolean;
  client_id?: number; engagement_id?: number; instance_id?: number;
  client_name?: string; engagement_name?: string;
  stats?: { cpu: string; mem: string; mem_pct: string } | null;
}
interface ContainersResp { docker_available: boolean; containers: Container[]; }

const STATE_COLOR: Record<string, string> = {
  running: "text-emerald-300 border-emerald-500/40",
  exited: "text-slate-400 border-edge",
  created: "text-amber-300 border-amber-500/40",
};

export default function ContainersPage() {
  const [showAll, setShowAll] = useState(false);
  const key = `/containers?all=${showAll}`;
  const { data, isLoading } = useSWR<ContainersResp>(key, fetcher, { refreshInterval: 4000 });
  const [active, setActive] = useState<{ ref: string; name: string; tab: "logs" | "shell" } | null>(null);
  const [pending, setPending] = useState<string>("");
  const [view, setView] = useState<"cluster" | "list">("cluster");

  async function act(ref: string, action: string) {
    setPending(`${ref}:${action}`);
    try {
      if (action === "remove" && active?.ref === ref) setActive(null);
      await api(`/containers/${ref}/${action}`, { method: "POST" });
      mutate(key);
    } catch (e: any) { alert(e.message); }
    finally { setPending(""); }
  }

  async function bulk(action: string, scope: { client_id?: number; engagement_id?: number }) {
    setPending(`bulk:${action}:${scope.client_id ?? scope.engagement_id}`);
    try {
      await api("/containers/bulk", { method: "POST", body: JSON.stringify({ action, ...scope }) });
      mutate(key);
    } catch (e: any) { alert(e.message); }
    finally { setPending(""); }
  }

  // Group: client → engagement → containers
  const groups = useMemo(() => {
    const cs = data?.containers || [];
    const byClient: Record<string, { name: string; client_id?: number; engs: Record<string, { name: string; engagement_id?: number; items: Container[] }> }> = {};
    for (const c of cs) {
      const ck = String(c.client_id ?? "none");
      const ek = String(c.engagement_id ?? "none");
      byClient[ck] ??= { name: c.client_name || (c.managed ? "Unassigned" : "External / Unmanaged"), client_id: c.client_id, engs: {} };
      byClient[ck].engs[ek] ??= { name: c.engagement_name || (c.managed ? "—" : "not managed by Temple Guard"), engagement_id: c.engagement_id, items: [] };
      byClient[ck].engs[ek].items.push(c);
    }
    return byClient;
  }, [data]);

  const running = (data?.containers || []).filter((c) => c.state === "running").length;

  return (
    <div className="p-8">
      <PageHeader title="Container Control Center"
        subtitle={data?.docker_available
          ? `${data.containers.length} container(s) · ${running} running · live stats`
          : "Docker not available"}>
        <div className="flex rounded-lg border border-edge overflow-hidden">
          <button className={`px-3 py-1.5 text-sm ${view === "cluster" ? "bg-accent text-ink" : "text-slate-300"}`} onClick={() => setView("cluster")}>⬡ Cluster</button>
          <button className={`px-3 py-1.5 text-sm ${view === "list" ? "bg-accent text-ink" : "text-slate-300"}`} onClick={() => setView("list")}>☰ List</button>
        </div>
        <button className={`btn ${showAll ? "btn-primary" : ""}`} onClick={() => setShowAll((v) => !v)}>
          {showAll ? "● Showing all containers" : "○ Temple Guard only"}
        </button>
        <button className="btn" onClick={() => mutate(key)}>↻ Refresh</button>
      </PageHeader>

      {isLoading ? <Spinner /> : !data?.docker_available ? (
        <div className="card p-6 text-sm text-slate-300">
          Docker isn’t reachable. Start Docker to manage live Kali instances and scan containers.
        </div>
      ) : (
        <div className={`grid grid-cols-1 gap-4 ${active ? "xl:grid-cols-3" : ""}`}>
          <div className={`space-y-5 ${active ? "xl:col-span-2" : ""}`}>
            {view === "cluster" && (
              <ClusterView containers={data?.containers || []} activeRef={active?.ref} pending={pending}
                onSelect={(ref, name, tab) => setActive({ ref, name, tab: tab || "logs" })}
                onAct={act} onBulk={bulk} />
            )}
            {view === "list" && (<>
            {Object.entries(groups).length === 0 && (
              <div className="card p-6 text-sm text-slate-400">
                No managed containers yet. Launch a Kali instance from the Consoles page or run an audit.
              </div>
            )}
            {Object.entries(groups).map(([ck, client]) => (
              <div key={ck} className="card p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-accent">◉</span>
                    <span className="font-semibold">{client.name}</span>
                  </div>
                  {client.client_id && (
                    <div className="flex gap-1.5">
                      <button className="btn text-xs py-1" disabled={!!pending} onClick={() => bulk("stop", { client_id: client.client_id })}>Stop all</button>
                      <button className="btn text-xs py-1" disabled={!!pending} onClick={() => bulk("restart", { client_id: client.client_id })}>Restart all</button>
                    </div>
                  )}
                </div>

                {Object.entries(client.engs).map(([ek, eng]) => (
                  <div key={ek} className="mb-3 last:mb-0">
                    <div className="flex items-center justify-between mb-1.5 pl-1">
                      <span className="text-xs text-slate-400">⛨ {eng.name}</span>
                      {eng.engagement_id && (
                        <div className="flex gap-1.5">
                          <button className="text-[11px] text-slate-400 hover:text-white" disabled={!!pending} onClick={() => bulk("stop", { engagement_id: eng.engagement_id })}>stop eng</button>
                          <span className="text-slate-600">·</span>
                          <button className="text-[11px] text-slate-400 hover:text-white" disabled={!!pending} onClick={() => bulk("restart", { engagement_id: eng.engagement_id })}>restart eng</button>
                        </div>
                      )}
                    </div>

                    {eng.items.map((c) => (
                      <div key={c.id} className={`rounded-lg border bg-panel2 p-3 mb-2 ${active?.ref === c.id ? "border-accent" : "border-edge"}`}>
                        <div className="flex items-center gap-3">
                          <span className={`chip text-[10px] ${STATE_COLOR[c.state] || "text-slate-400"}`}>● {c.state}</span>
                          <span className="font-mono text-sm flex-1 truncate">{c.name}</span>
                          <span className="chip text-[10px] text-slate-400">{c.role}</span>
                        </div>
                        <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-500 font-mono">
                          <span>{c.image}</span>
                          <span>· {c.id}</span>
                          <span>· {c.status}</span>
                          {c.stats && <span className="text-slate-400">· cpu {c.stats.cpu} · mem {c.stats.mem}</span>}
                        </div>
                        <div className="flex flex-wrap gap-1.5 mt-2.5">
                          <button className="btn text-xs py-1" disabled={c.state !== "running"} onClick={() => setActive({ ref: c.id, name: c.name, tab: "shell" })}>▮ Shell</button>
                          <button className="btn text-xs py-1" onClick={() => setActive({ ref: c.id, name: c.name, tab: "logs" })}>≡ Logs</button>
                          {c.state === "running"
                            ? <button className="btn text-xs py-1" disabled={!!pending} onClick={() => act(c.id, "stop")}>■ Stop</button>
                            : <button className="btn text-xs py-1" disabled={!!pending} onClick={() => act(c.id, "start")}>▶ Start</button>}
                          <button className="btn text-xs py-1" disabled={!!pending} onClick={() => act(c.id, "restart")}>↻ Restart</button>
                          <button className="btn text-xs py-1 hover:border-red-500/60 hover:text-red-300" disabled={!!pending} onClick={() => act(c.id, "remove")}>✕ Remove</button>
                        </div>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            ))}
            </>)}
          </div>

          {active && (
            <div className="xl:col-span-1">
              <div className="sticky top-8 space-y-2">
                <div className="flex items-center gap-2">
                  <button className={`btn text-xs py-1 ${active.tab === "logs" ? "btn-primary" : ""}`} onClick={() => setActive({ ...active, tab: "logs" })}>Logs</button>
                  <button className={`btn text-xs py-1 ${active.tab === "shell" ? "btn-primary" : ""}`} onClick={() => setActive({ ...active, tab: "shell" })}>Shell</button>
                  <span className="text-xs text-slate-400 font-mono truncate flex-1 ml-1">{active.name}</span>
                  <button className="btn text-xs py-1" onClick={() => setActive(null)}>✕ Close</button>
                </div>
                {active.tab === "logs"
                  ? <Terminal key={`logs-${active.ref}`} wsPath={`/containers/${active.ref}/logs`} readOnly title={`logs · ${active.name}`} heightClass="h-[460px]" />
                  : <Terminal key={`shell-${active.ref}`} wsPath={`/containers/${active.ref}/shell`} title={`shell · ${active.name}`} heightClass="h-[460px]" />}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

"use client";
import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import useSWR, { mutate } from "swr";
import { api, fetcher } from "@/lib/api";
import { PageHeader, Spinner } from "@/components/ui";

interface Endpoint { method: string; path: string; source?: string; status?: number | null; }
const METHOD_COLOR: Record<string, string> = {
  GET: "#22c55e", POST: "#3b82f6", PUT: "#eab308", PATCH: "#a855f7", DELETE: "#ef4444", OPTIONS: "#64748b",
};
const key = (e: { method: string; path: string }) => `${e.method} ${e.path}`;

interface TreeNode { seg: string; path: string; children: Map<string, TreeNode>; methods: string[]; }

function buildTree(eps: Endpoint[]): TreeNode {
  const root: TreeNode = { seg: "/", path: "/", children: new Map(), methods: [] };
  for (const ep of eps) {
    const segs = ep.path.split("/").filter(Boolean);
    if (!segs.length) { if (!root.methods.includes(ep.method)) root.methods.push(ep.method); continue; }
    let node = root, acc = "";
    for (const s of segs) {
      acc += "/" + s;
      if (!node.children.has(s)) node.children.set(s, { seg: s, path: acc, children: new Map(), methods: [] });
      node = node.children.get(s)!;
    }
    if (!node.methods.includes(ep.method)) node.methods.push(ep.method);
  }
  return root;
}
function nodeKeys(node: TreeNode): string[] {
  let out = node.methods.map((m) => key({ method: m, path: node.path }));
  node.children.forEach((c) => { out = out.concat(nodeKeys(c)); });
  return out;
}

export default function ApiTesterPage({ params }: { params: { id: string } }) {
  const router = useRouter();
  const tkey = `/targets/${params.id}`;
  const { data: target } = useSWR<any>(tkey, fetcher);
  const [busy, setBusy] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [methodFilter, setMethodFilter] = useState<Set<string>>(new Set());
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const endpoints: Endpoint[] = target?.extra?.discovered || [];
  const filtered = useMemo(() =>
    methodFilter.size ? endpoints.filter((e) => methodFilter.has(e.method)) : endpoints,
    [endpoints, methodFilter]);
  const tree = useMemo(() => buildTree(filtered), [filtered]);
  const allMethods = useMemo(() => Array.from(new Set(endpoints.map((e) => e.method))).sort(), [endpoints]);

  async function discover() {
    setBusy("discover");
    try { await api(`/targets/${params.id}/api/discover`, { method: "POST" }); mutate(tkey); }
    catch (e: any) { alert(e.message); } finally { setBusy(""); }
  }
  async function test(eps: { method: string; path: string }[]) {
    if (!eps.length) return;
    setBusy("test");
    try {
      await api(`/targets/${params.id}/api/test`, { method: "POST", body: JSON.stringify({ endpoints: eps }) });
      router.push(`/attacks/${params.id}`);
    } catch (e: any) { alert(e.message); setBusy(""); }
  }

  function toggle(k: string) {
    setSelected((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
  }
  function toggleNode(node: TreeNode) {
    const keys = nodeKeys(node);
    const allOn = keys.every((k) => selected.has(k));
    setSelected((s) => { const n = new Set(s); keys.forEach((k) => allOn ? n.delete(k) : n.add(k)); return n; });
  }
  const selectedEps = () => Array.from(selected).map((k) => {
    const i = k.indexOf(" "); return { method: k.slice(0, i), path: k.slice(i + 1) };
  });

  return (
    <div className="p-8">
      <div className="text-xs text-slate-400 mb-3">
        {target && <Link href={`/engagements/${target.engagement_id}`} className="hover:text-accent">{target.engagement_name}</Link>}
        {" / "}<span className="text-slate-500">API tester</span>
      </div>
      <PageHeader title={`◎ API — ${target?.value || params.id}`} subtitle="Discover endpoints, scope by level/method, and send bounded request batches">
        <button className="btn" disabled={!!busy} onClick={discover}>{busy === "discover" ? "Discovering…" : "⟲ Discover endpoints"}</button>
        <Link href={`/attacks/${params.id}`} className="btn">Results dashboard →</Link>
      </PageHeader>

      {!target ? <Spinner /> : !endpoints.length ? (
        <div className="card p-6 text-sm text-slate-300">
          No endpoints yet. Click <b>Discover endpoints</b> — Temple Guard reads an OpenAPI/Swagger spec if present,
          otherwise probes common paths. You can then select by level or method and run bounded tests.
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 card p-4">
            <div className="flex items-center gap-2 flex-wrap mb-3">
              <span className="label">{endpoints.length} endpoints · {selected.size} selected</span>
              <span className="flex-1" />
              {allMethods.map((m) => (
                <button key={m} onClick={() => setMethodFilter((s) => { const n = new Set(s); n.has(m) ? n.delete(m) : n.add(m); return n; })}
                  className="chip text-[10px] font-mono" style={{
                    color: METHOD_COLOR[m], borderColor: (methodFilter.has(m) ? METHOD_COLOR[m] : "#1e293b"),
                    background: methodFilter.has(m) ? METHOD_COLOR[m] + "22" : "transparent" }}>{m}</button>
              ))}
            </div>
            <div className="font-mono text-sm">
              <TreeView node={tree} depth={0} selected={selected} collapsed={collapsed}
                onToggleSel={toggle} onToggleNode={toggleNode}
                onCollapse={(p) => setCollapsed((s) => { const n = new Set(s); n.has(p) ? n.delete(p) : n.add(p); return n; })} />
            </div>
          </div>

          <div className="space-y-3">
            <div className="card p-4">
              <div className="label mb-2">Run requests</div>
              <p className="text-xs text-slate-400 mb-3">Each selected endpoint gets a hard-capped burst (8 requests); responses + latency are logged and analyzed (OWASP API Top 10).</p>
              <button className="btn btn-primary w-full mb-2" disabled={!!busy || !selected.size} onClick={() => test(selectedEps())}>
                {busy === "test" ? "Testing…" : `▶ Test selected (${selected.size})`}
              </button>
              <button className="btn w-full mb-2" disabled={!!busy} onClick={() => test(endpoints)}>▶ Test all ({endpoints.length})</button>
              <div className="flex gap-2">
                <button className="btn text-xs flex-1" onClick={() => setSelected(new Set(nodeKeys(tree)))}>Select all</button>
                <button className="btn text-xs flex-1" onClick={() => setSelected(new Set())}>Clear</button>
              </div>
            </div>
            <div className="card p-4 text-[11px] text-slate-400">
              <div className="label mb-1">Legend</div>
              Tick a folder to select its whole subtree, or individual methods. Filter by method with the chips above. Results stream to the attack dashboard.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function TreeView({ node, depth, selected, collapsed, onToggleSel, onToggleNode, onCollapse }: {
  node: TreeNode; depth: number; selected: Set<string>; collapsed: Set<string>;
  onToggleSel: (k: string) => void; onToggleNode: (n: TreeNode) => void; onCollapse: (p: string) => void;
}) {
  const children = Array.from(node.children.values()).sort((a, b) => a.seg.localeCompare(b.seg));
  const keys = nodeKeys(node);
  const selCount = keys.filter((k) => selected.has(k)).length;
  const allOn = keys.length > 0 && selCount === keys.length;
  const isCollapsed = collapsed.has(node.path);
  const hasKids = children.length > 0;

  return (
    <div>
      {depth > 0 && (
        <div className="flex items-center gap-1.5 py-0.5 hover:bg-panel2 rounded" style={{ paddingLeft: depth * 14 }}>
          {hasKids
            ? <button className="w-4 text-slate-500" onClick={() => onCollapse(node.path)}>{isCollapsed ? "▸" : "▾"}</button>
            : <span className="w-4" />}
          <input type="checkbox" checked={allOn} ref={(el) => { if (el) el.indeterminate = selCount > 0 && !allOn; }}
            onChange={() => onToggleNode(node)} />
          <span className="text-slate-300">/{node.seg}</span>
          <span className="text-[10px] text-slate-500">{selCount}/{keys.length}</span>
          {node.methods.map((m) => {
            const k = key({ method: m, path: node.path });
            return (
              <button key={m} onClick={() => onToggleSel(k)}
                className="chip text-[9px] font-mono" style={{
                  color: METHOD_COLOR[m], borderColor: selected.has(k) ? METHOD_COLOR[m] : "#1e293b",
                  background: selected.has(k) ? METHOD_COLOR[m] + "22" : "transparent" }}>
                {selected.has(k) ? "✓ " : ""}{m}
              </button>
            );
          })}
        </div>
      )}
      {!isCollapsed && children.map((c) => (
        <TreeView key={c.path} node={c} depth={depth + 1} selected={selected} collapsed={collapsed}
          onToggleSel={onToggleSel} onToggleNode={onToggleNode} onCollapse={onCollapse} />
      ))}
    </div>
  );
}

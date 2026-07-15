"use client";
import { useState } from "react";
import useSWR, { mutate } from "swr";
import Link from "next/link";
import { api, fetcher } from "@/lib/api";
import type { Client } from "@/lib/types";
import { PageHeader, AuthBadge, Spinner } from "@/components/ui";

const EMPTY = { name: "", industry: "", contact_email: "", authorization_status: "pending", scope_notes: "" };

export default function ClientsPage() {
  const { data, isLoading } = useSWR<Client[]>("/clients", fetcher);
  const [open, setOpen] = useState(false);
  const [editId, setEditId] = useState<number | null>(null);
  const [form, setForm] = useState({ ...EMPTY });
  const [busy, setBusy] = useState(false);

  function startCreate() { setEditId(null); setForm({ ...EMPTY }); setOpen(true); }
  function startEdit(c: Client) {
    setEditId(c.id);
    setForm({ name: c.name, industry: c.industry || "", contact_email: c.contact_email || "",
      authorization_status: c.authorization_status, scope_notes: c.scope_notes || "" });
    setOpen(true);
  }

  async function save() {
    setBusy(true);
    try {
      if (editId) await api(`/clients/${editId}`, { method: "PATCH", body: JSON.stringify(form) });
      else await api("/clients", { method: "POST", body: JSON.stringify(form) });
      setOpen(false); setEditId(null); setForm({ ...EMPTY });
      mutate("/clients");
    } finally { setBusy(false); }
  }

  async function del(c: Client) {
    const n = c.engagement_count ?? 0;
    if (!confirm(`Delete client "${c.name}"${n ? ` and its ${n} engagement(s) + all findings` : ""}? This cannot be undone.`)) return;
    await api(`/clients/${c.id}`, { method: "DELETE" });
    mutate("/clients");
  }

  return (
    <div className="p-8">
      <PageHeader title="Clients" subtitle="Each client carries its own authorization status and scope">
        <button className="btn btn-primary" onClick={startCreate}>＋ Add Client</button>
      </PageHeader>

      {open && (
        <div className="card p-5 mb-5 max-w-2xl">
          <div className="label mb-3">{editId ? "Edit client" : "New client"}</div>
          <div className="grid grid-cols-2 gap-3">
            <div><div className="label mb-1">Name</div><input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
            <div><div className="label mb-1">Industry</div><input className="input" value={form.industry} onChange={(e) => setForm({ ...form, industry: e.target.value })} /></div>
            <div><div className="label mb-1">Contact email</div><input className="input" value={form.contact_email} onChange={(e) => setForm({ ...form, contact_email: e.target.value })} /></div>
            <div><div className="label mb-1">Authorization</div>
              <select className="input" value={form.authorization_status} onChange={(e) => setForm({ ...form, authorization_status: e.target.value })}>
                <option value="pending">pending</option>
                <option value="authorized">authorized</option>
                <option value="revoked">revoked</option>
              </select>
            </div>
            <div className="col-span-2"><div className="label mb-1">Scope notes / SOW</div><input className="input" value={form.scope_notes} onChange={(e) => setForm({ ...form, scope_notes: e.target.value })} /></div>
          </div>
          <div className="flex gap-2 mt-4">
            <button className="btn btn-primary" disabled={busy || !form.name} onClick={save}>{busy ? "Saving…" : editId ? "Save changes" : "Save client"}</button>
            <button className="btn" onClick={() => setOpen(false)}>Cancel</button>
          </div>
        </div>
      )}

      {isLoading ? <Spinner /> : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {(data || []).map((c) => (
            <div key={c.id} className="card p-5 hover:border-accent/40 transition flex flex-col">
              <div className="flex items-start justify-between">
                <Link href={`/engagements?client=${c.id}`} className="min-w-0">
                  <div className="font-semibold text-white hover:text-accent truncate">{c.name}</div>
                  <div className="text-xs text-slate-400">{c.industry || "—"}</div>
                </Link>
                <AuthBadge status={c.authorization_status} />
              </div>
              {c.scope_notes && <p className="text-xs text-slate-400 mt-3 line-clamp-2">{c.scope_notes}</p>}
              <div className="flex gap-4 mt-4 text-sm">
                <span className="text-slate-300"><b className="text-white">{c.engagement_count ?? 0}</b> engagements</span>
                <span className="text-slate-300"><b className="text-white">{c.finding_count ?? 0}</b> findings</span>
              </div>
              <div className="flex gap-1.5 mt-4 pt-3 border-t border-edge">
                <Link href={`/engagements?client=${c.id}`} className="btn text-xs py-1 flex-1">Engagements →</Link>
                <button className="btn text-xs py-1" onClick={() => startEdit(c)}>✎ Edit</button>
                <button className="btn text-xs py-1 hover:border-red-500/60 hover:text-red-300" onClick={() => del(c)}>🗑</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

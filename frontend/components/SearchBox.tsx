"use client";
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { fetcher } from "@/lib/api";

interface Hit { type: string; id: number; title: string; subtitle?: string; href: string; }

const ICON: Record<string, string> = {
  client: "◉", engagement: "⛨", finding: "▣", asset: "⬡", target: "◎",
};

export default function SearchBox() {
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<Hit[]>([]);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const router = useRouter();
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (q.trim().length < 1) { setHits([]); return; }
    const t = setTimeout(() => {
      fetcher(`/search?q=${encodeURIComponent(q.trim())}`)
        .then((d: any) => { setHits(d.results || []); setActive(0); setOpen(true); })
        .catch(() => setHits([]));
    }, 180);
    return () => clearTimeout(t);
  }, [q]);

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  function go(h: Hit) { setOpen(false); setQ(""); router.push(h.href); }

  function onKey(e: React.KeyboardEvent) {
    if (!open || !hits.length) return;
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(a + 1, hits.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); go(hits[active]); }
    else if (e.key === "Escape") setOpen(false);
  }

  return (
    <div ref={boxRef} className="relative px-2 mb-4">
      <div className="flex items-center gap-2 bg-ink border border-edge rounded-lg px-2.5 py-1.5 focus-within:border-accent">
        <span className="text-slate-500 text-sm">⌕</span>
        <input
          className="w-full bg-transparent text-sm outline-none placeholder:text-slate-600"
          placeholder="Search…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onFocus={() => q && setOpen(true)}
          onKeyDown={onKey}
        />
      </div>
      {open && hits.length > 0 && (
        <div className="absolute z-30 left-2 top-full mt-1 w-80 bg-panel2 border border-edge rounded-lg shadow-2xl max-h-96 overflow-auto">
          {hits.map((h, i) => (
            <button key={`${h.type}-${h.id}`} onMouseDown={(e) => { e.preventDefault(); go(h); }}
              onMouseEnter={() => setActive(i)}
              className={`w-full text-left px-3 py-2 flex items-center gap-2.5 ${i === active ? "bg-accent/15" : "hover:bg-panel"}`}>
              <span className="w-4 text-center text-accent/80">{ICON[h.type] || "•"}</span>
              <span className="flex-1 min-w-0">
                <span className="block text-sm truncate">{h.title}</span>
                <span className="block text-[10px] text-slate-500 truncate">{h.type} · {h.subtitle}</span>
              </span>
            </button>
          ))}
        </div>
      )}
      {open && q.trim() && hits.length === 0 && (
        <div className="absolute z-30 left-2 top-full mt-1 w-80 bg-panel2 border border-edge rounded-lg p-3 text-xs text-slate-400">No matches for “{q}”.</div>
      )}
    </div>
  );
}

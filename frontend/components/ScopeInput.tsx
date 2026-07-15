"use client";
import { useMemo, useRef, useState } from "react";
import useSWR from "swr";
import { fetcher } from "@/lib/api";

/**
 * Chip input for an engagement's authorized scope.
 * - type a host/URL, press Enter/comma/Tab to add it as a chip
 * - fuzzy-autocomplete from hosts the client already has
 * - "Any target (*)" adds a wildcard that authorizes everything
 */
export default function ScopeInput({
  value, onChange, clientId,
}: {
  value: string[];
  onChange: (next: string[]) => void;
  clientId?: string | number | null;
}) {
  const [text, setText] = useState("");
  const [focus, setFocus] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const { data: suggestions } = useSWR<string[]>(
    clientId ? `/clients/${clientId}/scope-suggestions` : null, fetcher);

  const wildcard = value.includes("*");

  const matches = useMemo(() => {
    const pool = (suggestions || []).filter((s) => !value.includes(s));
    const q = text.trim().toLowerCase();
    if (!q) return pool.slice(0, 8);
    // simple fuzzy: keep items containing all query chars in order
    const fuzzy = (s: string) => {
      let i = 0;
      for (const ch of s.toLowerCase()) if (ch === q[i]) i++;
      return i === q.length;
    };
    return pool.filter((s) => s.toLowerCase().includes(q) || fuzzy(s)).slice(0, 8);
  }, [text, suggestions, value]);

  function add(v: string) {
    const t = v.trim().replace(/,$/, "");
    if (!t) return;
    if (!value.includes(t)) onChange([...value, t]);
    setText("");
    inputRef.current?.focus();
  }
  function remove(v: string) { onChange(value.filter((x) => x !== v)); }

  function onKey(e: React.KeyboardEvent) {
    if (["Enter", ",", "Tab"].includes(e.key) && text.trim()) {
      e.preventDefault(); add(text);
    } else if (e.key === "Backspace" && !text && value.length) {
      remove(value[value.length - 1]);
    }
  }

  return (
    <div>
      <div className={`min-h-[42px] flex flex-wrap items-center gap-1.5 bg-ink border rounded-lg px-2 py-1.5 ${focus ? "border-accent" : "border-edge"}`}>
        {value.map((v) => (
          <span key={v} className={`chip text-xs ${v === "*" ? "text-amber-300 border-amber-500/50" : "text-accent border-accent/40"}`}>
            {v === "*" ? "✶ any target" : v}
            <button type="button" className="ml-1.5 text-slate-400 hover:text-white" onClick={() => remove(v)}>×</button>
          </span>
        ))}
        <div className="relative flex-1 min-w-[140px]">
          <input
            ref={inputRef}
            className="w-full bg-transparent text-sm outline-none py-1 font-mono"
            placeholder={value.length ? "add another…" : "type a host or URL, e.g. app.example.com"}
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={onKey}
            onFocus={() => setFocus(true)}
            onBlur={() => setTimeout(() => setFocus(false), 150)}
          />
          {focus && matches.length > 0 && (
            <div className="absolute z-20 left-0 right-0 mt-1 bg-panel2 border border-edge rounded-lg shadow-xl max-h-56 overflow-auto">
              <div className="px-2 py-1 text-[10px] text-slate-500 uppercase tracking-wide">From this client</div>
              {matches.map((m) => (
                <button key={m} type="button" onMouseDown={(e) => { e.preventDefault(); add(m); }}
                  className="block w-full text-left px-3 py-1.5 text-sm hover:bg-accent/15 font-mono">{m}</button>
              ))}
            </div>
          )}
        </div>
      </div>
      <div className="flex items-center gap-2 mt-1.5">
        {text.trim() && (
          <button type="button" className="text-[11px] text-accent hover:underline" onMouseDown={(e) => { e.preventDefault(); add(text); }}>
            ＋ add &ldquo;{text.trim()}&rdquo;
          </button>
        )}
        {!wildcard ? (
          <button type="button" className="text-[11px] text-amber-300 hover:underline" onClick={() => add("*")}>
            ✶ Any target (no host restriction)
          </button>
        ) : (
          <span className="text-[11px] text-amber-300">Scope is unrestricted — every target you add is authorized.</span>
        )}
      </div>
      <p className="text-[11px] text-slate-500 mt-1">
        Your authorization boundary — scans refuse anything not listed here. Use{" "}
        <span className="text-amber-300">Any target</span> only for environments you fully own.
      </p>
    </div>
  );
}

"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import SearchBox from "./SearchBox";

const NAV: { href: string; label: string; icon: string; badge?: string }[] = [
  { href: "/", label: "Dashboard", icon: "▣" },
  { href: "/clients", label: "Clients", icon: "◉" },
  { href: "/engagements", label: "Engagements", icon: "⛨" },
  { href: "/topology", label: "Topology", icon: "⬡" },
  { href: "/consoles", label: "Kali Consoles", icon: "▮" },
  { href: "/containers", label: "Control Center", icon: "▦" },
  { href: "/evidence", label: "Evidence", icon: "▣" },
  { href: "/reports", label: "Reports", icon: "▤" },
  { href: "/team-ops", label: "Team Ops", icon: "❖" },
  { href: "/playbooks", label: "Playbooks", icon: "▦" },
];

export default function Sidebar() {
  const path = usePathname();
  return (
    <aside className="w-60 shrink-0 border-r border-edge bg-panel/60 backdrop-blur px-3 py-5 flex flex-col">
      <div className="px-2 mb-7">
        <div className="flex items-center gap-2.5">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logo.svg" alt="Temple Guard" className="h-10 w-10 drop-shadow-[0_0_6px_rgba(255,214,10,0.25)]" />
          <div>
            <div className="font-semibold leading-tight">Temple Guard</div>
            <div className="text-[10px] uppercase tracking-widest text-slate-500">Authorized Pentest Ops</div>
          </div>
        </div>
      </div>
      <SearchBox />
      <nav className="space-y-1">
        {NAV.map((n) => {
          const active = n.href === "/" ? path === "/" : path.startsWith(n.href);
          return (
            <Link
              key={n.href}
              href={n.href}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition ${
                active ? "bg-accent/15 text-white border border-accent/40" : "text-slate-300 hover:bg-panel2"
              }`}
            >
              <span className="w-4 text-center opacity-80">{n.icon}</span>
              <span className="flex-1">{n.label}</span>
              {n.badge && <span className="chip text-[9px] text-amber-300 border-amber-500/40">{n.badge}</span>}
            </Link>
          );
        })}
      </nav>
      <div className="mt-auto px-2 pt-6 text-[10px] text-slate-500 leading-relaxed">
        <div className="chip text-emerald-300 border-emerald-500/40 mb-2">● scope enforcement on</div>
        <p>All scans are restricted to authorized targets. v0.1.0</p>
      </div>
    </aside>
  );
}

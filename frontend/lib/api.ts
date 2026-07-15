const BASE = "/api";

export async function api<T = any>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail || detail;
    } catch {}
    throw new Error(detail);
  }
  return res.json();
}

export const fetcher = (path: string) => api(path);

// Direct WebSocket to the backend (proxying ws through Next is unreliable).
export function wsUrl(path: string): string {
  const base = process.env.NEXT_PUBLIC_WS_BASE || "ws://localhost:8000";
  return `${base}/api${path}`;
}

export const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#64748b",
};

export const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

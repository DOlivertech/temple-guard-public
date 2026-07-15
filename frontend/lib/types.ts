export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Client {
  id: number;
  name: string;
  slug: string;
  industry?: string;
  contact_email?: string;
  authorization_status: "pending" | "authorized" | "revoked";
  scope_notes?: string;
  engagement_count?: number;
  finding_count?: number;
}

export interface Engagement {
  id: number;
  client_id: number;
  client_name?: string;
  name: string;
  status: "draft" | "active" | "completed" | "archived";
  standards: string[];
  scope_targets: string[];
  authorization_ref?: string;
  authorized_by?: string;
  provisioner: string;
  finding_count?: number;
  findings_by_severity?: Record<string, number>;
}

export interface Finding {
  id: number;
  engagement_id: number;
  title: string;
  severity: Severity;
  category?: string;
  standard_refs: string[];
  cvss?: number;
  description?: string;
  evidence?: string;
  evidence_path?: string;
  remediation?: string;
  status: string;
}

export interface Execution {
  engine: "container" | "in-process" | "simulated";
  image?: string | null;
  label?: string;
}

export interface ScanRun {
  id: number;
  module: string;
  standard?: string;
  target: string;
  status: string;
  provisioner: string;
  execution?: Execution;
  raw_output?: string;
}

export interface Asset {
  id: number;
  hostname?: string;
  ip?: string;
  asset_type: string;
  open_ports: { port: number; service: string; banner?: string }[];
}

export interface AuditTarget {
  id: number;
  engagement_id: number;
  kind: "web" | "app" | "api" | "redteam" | "phone";
  value: string;
  os?: "linux" | "windows" | "macos" | null;
  operation?: string;
  team?: string;
  extra?: { discovered?: { method: string; path: string }[] } & Record<string, any>;
  label?: string;
  last_status?: string;
}

export interface Standard {
  id: string;
  name: string;
  framework: string;
  category: string;
  description: string;
  references: string[];
  available: boolean;
}

export interface Control {
  ref: string;
  framework: string;
  control: string;
  title: string;
  url: string | null;
}

export interface EvidenceItem {
  id: number;
  title: string;
  severity: Severity;
  category?: string;
  cvss?: number;
  description?: string;
  evidence?: string;
  evidence_path?: string;
  has_screenshot: boolean;
  remediation?: string;
  status: string;
  engagement_id: number;
  engagement_name?: string;
  client_id?: number;
  client_name?: string;
  module?: string;
  standard?: string;
  target?: string;
  controls: Control[];
  created_at?: string;
}

export interface EvidenceResponse {
  count: number;
  with_screenshots: number;
  by_severity: Record<string, number>;
  by_framework: Record<string, number>;
  items: EvidenceItem[];
}

export interface Dashboard {
  clients: number;
  engagements: number;
  active_engagements: number;
  scans: number;
  scans_running: number;
  scans_queued: number;
  findings: number;
  findings_by_severity: Record<string, number>;
  open_critical: number;
  recent_scans: ScanRun[];
}

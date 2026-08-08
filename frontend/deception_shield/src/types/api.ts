// Generated from the Honeypot-as-a-Service backend contract.

export type HoneypotType = "cowrie" | "dionaea" | "wp-decoy" | "rdp-decoy" | "smb-decoy";

export type EventType =
  | "login_attempt"
  | "command_exec"
  | "file_download"
  | "exploit_probe"
  | "port_scan";

export type Technique =
  | "brute_force"
  | "credential_reuse"
  | "payload_drop"
  | "cve_exploit_attempt";

export type Severity = "low" | "medium" | "high" | "critical";

export interface Geo {
  country: string;
  city: string;
  lat: number;
  lon: number;
  asn: string;
  org: string;
}

export interface Reputation {
  abuseipdb_score: number;
  known_malicious: boolean;
}

export interface AttackEvent {
  id: string;
  honeypot_id: string;
  honeypot_type: HoneypotType;
  attacker_ip: string;
  geo: Geo;
  reputation: Reputation;
  event_type: EventType;
  technique: Technique;
  mitre_attck_id: string;
  payload: string;
  session_id: string;
  timestamp: string;
  severity: Severity;
}

export interface Paginated<T> {
  items: T[];
  page: number;
  page_size: number;
  total: number;
}

export interface EventQuery {
  honeypot?: string;
  severity?: Severity;
  technique?: Technique;
  from?: string;
  to?: string;
  page?: number;
}

export interface TerminalFrame {
  /** milliseconds since session start */
  offset_ms: number;
  data: string;
}

export interface SessionDetail {
  id: string;
  honeypot_id: string;
  honeypot_type: HoneypotType;
  attacker_ip: string;
  started_at: string;
  ended_at: string;
  events: AttackEvent[];
  /** Raw TTY log frames (Cowrie sessions only) */
  tty_log: string | null;
  commands: string[] | null;
  duration_seconds: number | null;
}

export interface AttackerProfile {
  id: string;
  ip: string;
  geo: Geo;
  reputation: Reputation;
  first_seen: string;
  last_seen: string;
  total_events: number;
  honeypots_hit: string[];
  is_blocked: boolean;
  threat_score: number;
  techniques_used: string[];
}

export interface Stats {
  attack_timeline: { timestamp: string; count: number }[];
  top_attacking_countries: { country: string; count: number }[];
  top_techniques: { technique: Technique; count: number }[];
  events_per_honeypot: Record<string, number>;
  total_events: number;
  total_attackers: number;
  active_honeypots: number;
  blocked_ips: number;
  severity_breakdown: Record<string, number>;
}

export type HoneypotStatus = "running" | "stopped" | "deploying" | "error";

export interface Honeypot {
  id: string;
  type: HoneypotType;
  deployed_at: string;
  region: string;
  status: HoneypotStatus;
  ip_address: string;
}

export interface BlocklistEntry {
  ip: string;
  blocked_at: string;
  expires_at: string;
  reason: string;
  rule_triggered: string;
  action_taken: string;
}

export interface ResponseRule {
  id: string;
  name: string;
  event_type: EventType | null;
  threshold_count: number;
  threshold_window_seconds: number;
  block_duration_hours: number;
  is_enabled: boolean;
  description?: string;
  honeypot_type?: string;
  severity_filter?: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
}

export interface Heartbeat {
  type: "stats_heartbeat";
  data: Stats;
}

export interface LiveEventWrapper {
  type: "event";
  data: AttackEvent;
}

export type LiveMessage = LiveEventWrapper | Heartbeat;

// --- Threat Assistant (RAG over live/historical honeypot telemetry) ---

/** A grounding reference the assistant's answer is based on, surfaced so the
 * operator can verify the claim rather than trust it blindly. */
export interface AssistantCitation {
  label: string; // e.g. "4 events · 203.0.113.45 · cowrie-ssh-01"
  event_id?: string;
  session_id?: string;
  attacker_ip?: string;
}

export interface AssistantMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  citations?: AssistantCitation[];
  created_at: string;
}

export interface AssistantQueryRequest {
  question: string;
  conversation_id?: string;
}

export interface AssistantQueryResponse {
  conversation_id: string;
  message: AssistantMessage;
  retrieved_event_count: number;
}

export function isHeartbeat(msg: LiveMessage): msg is Heartbeat {
  return msg.type === "stats_heartbeat";
}

import type { AttackEvent, Severity } from "@/types/api";
import type { FeedFilters } from "@/store/ui";

export const SEVERITY_ORDER: Severity[] = ["low", "medium", "high", "critical"];

export const SEVERITY_TOKEN: Record<Severity, string> = {
  low: "var(--sev-low)",
  medium: "var(--sev-medium)",
  high: "var(--sev-high)",
  critical: "var(--sev-critical)",
};

export const SEVERITY_TEXT: Record<Severity, string> = {
  low: "text-sev-low",
  medium: "text-sev-medium",
  high: "text-sev-high",
  critical: "text-sev-critical",
};

export const SEVERITY_BG: Record<Severity, string> = {
  low: "bg-sev-low/12 text-sev-low",
  medium: "bg-sev-medium/12 text-sev-medium",
  high: "bg-sev-high/14 text-sev-high",
  critical: "bg-sev-critical/16 text-sev-critical",
};

/** Pure filter used by the live event feed (unit tested). */
export function matchesFilters(event: AttackEvent, f: FeedFilters): boolean {
  if (f.honeypot !== "all" && event.honeypot_id !== f.honeypot) return false;
  if (f.technique !== "all" && event.technique !== f.technique) return false;
  if (f.severity !== "all" && event.severity !== f.severity) return false;
  if (f.query.trim()) {
    const q = f.query.trim().toLowerCase();
    const haystack = `${event.attacker_ip} ${event.geo.country} ${event.geo.org} ${event.payload} ${event.mitre_attck_id}`;
    if (!haystack.toLowerCase().includes(q)) return false;
  }
  return true;
}

export function filterEvents(events: AttackEvent[], f: FeedFilters): AttackEvent[] {
  return events.filter((e) => matchesFilters(e, f));
}

export function formatTime(iso: string) {
  const d = new Date(iso);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

export function relativeTime(iso: string) {
  const diff = Date.now() - Date.parse(iso);
  const mins = Math.round(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

export function countdown(iso: string) {
  const ms = Date.parse(iso) - Date.now();
  if (ms <= 0) return "expired";
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

import type { AttackEvent, Severity, Technique } from "@/types/api";

/**
 * This module is the mock-mode stand-in for the backend's real RAG pipeline
 * (embedding search over event summaries in pgvector + an LLM call grounded
 * on the retrieved rows — see the backend build prompt, "Threat Assistant"
 * section). It does real retrieval and real aggregation over whatever events
 * are currently in the mock store, it just skips the embedding/LLM step and
 * synthesizes the answer with templates instead. The shape of the result
 * (answer + citations + retrieved_event_count) matches what the live backend
 * returns, so swapping USE_MOCK off requires no frontend changes.
 */

const TECHNIQUE_KEYWORDS: Record<Technique, string[]> = {
  brute_force: ["brute force", "brute-force", "credential guessing", "password spray"],
  credential_reuse: ["credential reuse", "reused credential", "known password"],
  payload_drop: ["payload", "malware", "dropped file", "download"],
  cve_exploit_attempt: ["cve", "exploit", "vulnerability"],
};

const SEVERITY_KEYWORDS: Severity[] = ["critical", "high", "medium", "low"];

const TIME_WINDOWS: { pattern: RegExp; minutes: number }[] = [
  { pattern: /last\s+(\d+)\s*(?:minutes?|mins?)/i, minutes: 0 }, // resolved dynamically below
  { pattern: /last\s+hour|past\s+hour/i, minutes: 60 },
  { pattern: /last\s+15\s*(?:minutes?|mins?)/i, minutes: 15 },
  { pattern: /last\s+24\s*h(?:ours?)?|today|past\s+day/i, minutes: 24 * 60 },
  { pattern: /last\s+week|past\s+week/i, minutes: 7 * 24 * 60 },
];

export interface ParsedIntent {
  ip?: string;
  honeypotId?: string;
  severity?: Severity;
  technique?: Technique;
  windowMinutes?: number;
}

export function parseIntent(question: string, knownHoneypotIds: string[]): ParsedIntent {
  const q = question.toLowerCase();
  const intent: ParsedIntent = {};

  const ipMatch = question.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/);
  if (ipMatch) intent.ip = ipMatch[0];

  for (const id of knownHoneypotIds) {
    if (q.includes(id.toLowerCase())) {
      intent.honeypotId = id;
      break;
    }
  }
  if (!intent.honeypotId) {
    if (q.includes("wordpress") || q.includes("wp-admin")) intent.honeypotId = "wp-decoy";
    else if (q.includes("rdp")) intent.honeypotId = "rdp-decoy";
    else if (q.includes("ssh") || q.includes("cowrie")) intent.honeypotId = "cowrie";
    else if (q.includes("smb") || q.includes("file server")) intent.honeypotId = "smb-decoy";
  }

  for (const sev of SEVERITY_KEYWORDS) {
    if (q.includes(sev)) {
      intent.severity = sev;
      break;
    }
  }

  for (const [technique, keywords] of Object.entries(TECHNIQUE_KEYWORDS) as [
    Technique,
    string[],
  ][]) {
    if (keywords.some((k) => q.includes(k))) {
      intent.technique = technique;
      break;
    }
  }

  const explicitMinutes = question.match(/last\s+(\d+)\s*(?:minutes?|mins?)/i);
  if (explicitMinutes?.[1]) {
    intent.windowMinutes = Number(explicitMinutes[1]);
  } else {
    for (const w of TIME_WINDOWS.slice(1)) {
      if (w.pattern.test(question)) {
        intent.windowMinutes = w.minutes;
        break;
      }
    }
  }

  return intent;
}

export function retrieveEvents(events: AttackEvent[], intent: ParsedIntent): AttackEvent[] {
  const now = Date.now();
  return events
    .filter((e) => (intent.ip ? e.attacker_ip === intent.ip : true))
    .filter((e) => (intent.honeypotId ? e.honeypot_id.includes(intent.honeypotId) : true))
    .filter((e) => (intent.severity ? e.severity === intent.severity : true))
    .filter((e) => (intent.technique ? e.technique === intent.technique : true))
    .filter((e) =>
      intent.windowMinutes ? now - Date.parse(e.timestamp) <= intent.windowMinutes * 60_000 : true,
    )
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
}

export interface SynthesizedAnswer {
  content: string;
  citations: { label: string; event_id: string; attacker_ip: string; session_id: string }[];
}

export function synthesizeAnswer(
  question: string,
  intent: ParsedIntent,
  matched: AttackEvent[],
): SynthesizedAnswer {
  if (matched.length === 0) {
    return {
      content:
        "No events in the current window match that. Try widening the time range or dropping a filter (IP, honeypot, severity, or technique).",
      citations: [],
    };
  }

  const distinctIps = new Set(matched.map((e) => e.attacker_ip));
  const byHoneypot = new Map<string, number>();
  for (const e of matched) byHoneypot.set(e.honeypot_id, (byHoneypot.get(e.honeypot_id) ?? 0) + 1);
  const topHoneypots = [...byHoneypot.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);

  const critical = matched.filter((e) => e.severity === "critical").length;

  const scopeBits: string[] = [];
  if (intent.ip) scopeBits.push(`from ${intent.ip}`);
  if (intent.honeypotId) scopeBits.push(`against ${intent.honeypotId} decoys`);
  if (intent.technique) scopeBits.push(`using ${intent.technique.replace(/_/g, " ")}`);
  if (intent.severity) scopeBits.push(`at ${intent.severity} severity`);
  if (intent.windowMinutes) {
    const label =
      intent.windowMinutes >= 1440
        ? `${Math.round(intent.windowMinutes / 1440)}d`
        : intent.windowMinutes >= 60
          ? `${Math.round(intent.windowMinutes / 60)}h`
          : `${intent.windowMinutes}m`;
    scopeBits.push(`in the last ${label}`);
  }
  const scope = scopeBits.length ? ` ${scopeBits.join(" ")}` : "";

  const lines = [
    `Found ${matched.length} event${matched.length === 1 ? "" : "s"}${scope}, from ${distinctIps.size} distinct IP${distinctIps.size === 1 ? "" : "s"}.`,
  ];
  if (topHoneypots.length) {
    lines.push(
      `Top decoys hit: ${topHoneypots.map(([id, n]) => `${id} (${n})`).join(", ")}.`,
    );
  }
  if (critical > 0) {
    lines.push(`${critical} of those event${critical === 1 ? " is" : "s are"} critical severity.`);
  }

  const citations = matched.slice(0, 5).map((e) => ({
    label: `${e.severity} · ${e.honeypot_id} · ${e.attacker_ip}`,
    event_id: e.id,
    attacker_ip: e.attacker_ip,
    session_id: e.session_id,
  }));

  return { content: lines.join(" "), citations };
}

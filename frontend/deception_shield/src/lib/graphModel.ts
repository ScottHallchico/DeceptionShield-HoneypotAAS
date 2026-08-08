import type { AttackEvent, Severity } from "@/types/api";
import { SEVERITY_ORDER } from "./severity";

export interface GraphNode {
  id: string;
  kind: "core" | "honeypot" | "attacker";
  label: string;
  events: number;
  severity: Severity;
  country?: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  events: number;
}

export interface GraphModel {
  nodes: Record<string, GraphNode>;
  edges: Record<string, GraphEdge>;
}

export const CORE_ID = "core";

export function emptyGraph(): GraphModel {
  return {
    nodes: {
      [CORE_ID]: {
        id: CORE_ID,
        kind: "core",
        label: "Your Honeypot Network",
        events: 0,
        severity: "low",
      },
    },
    edges: {},
  };
}

function worse(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

/**
 * Folds an attack event into the graph model. Returns the same object mutated
 * in place plus the list of ids that are newly added (used to pulse them).
 */
export function applyEvent(
  model: GraphModel,
  event: AttackEvent,
): { added: string[]; touched: string[] } {
  const added: string[] = [];
  const attackerId = `ip:${event.attacker_ip}`;
  const honeypotId = `hp:${event.honeypot_id}`;

  if (!model.nodes[honeypotId]) {
    model.nodes[honeypotId] = {
      id: honeypotId,
      kind: "honeypot",
      label: event.honeypot_id,
      events: 0,
      severity: "low",
    };
    added.push(honeypotId);
    const spineId = `e:${CORE_ID}->${honeypotId}`;
    model.edges[spineId] = { id: spineId, source: CORE_ID, target: honeypotId, events: 0 };
  }
  const honeypot = model.nodes[honeypotId]!;
  honeypot.events += 1;

  const existing = model.nodes[attackerId];
  if (existing) {
    existing.events += 1;
    existing.severity = worse(existing.severity, event.severity);
  } else {
    model.nodes[attackerId] = {
      id: attackerId,
      kind: "attacker",
      label: event.attacker_ip,
      events: 1,
      severity: event.severity,
      country: event.geo.country,
    };
    added.push(attackerId);
  }

  const edgeId = `e:${attackerId}->${honeypotId}`;
  const edge = model.edges[edgeId];
  if (edge) edge.events += 1;
  else {
    model.edges[edgeId] = { id: edgeId, source: attackerId, target: honeypotId, events: 1 };
    added.push(edgeId);
  }

  model.nodes[CORE_ID]!.events += 1;
  return { added, touched: [attackerId, honeypotId] };
}

export function buildGraph(events: AttackEvent[]): GraphModel {
  const model = emptyGraph();
  for (const e of events) applyEvent(model, e);
  return model;
}

export function nodeSize(node: GraphNode) {
  if (node.kind === "core") return 74;
  if (node.kind === "honeypot") return 34;
  return Math.min(46, 14 + Math.sqrt(node.events) * 5);
}

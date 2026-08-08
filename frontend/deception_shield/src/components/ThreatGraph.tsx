import { useEffect, useRef, useState } from "react";
import type { Core, ElementDefinition } from "cytoscape";
import { useLiveEventListener } from "@/hooks/useLiveEvents";
import { useLiveContext } from "@/context/LiveEventsProvider";
import {
  CORE_ID,
  applyEvent,
  buildGraph,
  nodeSize,
  type GraphModel,
  type GraphNode,
} from "@/lib/graphModel";
import { SEVERITY_TOKEN } from "@/lib/severity";

// Cytoscape renders to canvas and cannot resolve CSS custom properties,
// so the graph keeps literal values mirroring the design tokens.
const C = {
  primary: "#7fe3d4",
  bg: "#141a21",
  honeypot: "#7c8b9c",
  attackerLabel: "#b9c2cd",
  honeypotLabel: "#9fb0bf",
  edge: "#3a4552",
  sev: {
    low: "#69dcc2",
    medium: "#e7c164",
    high: "#e88c4a",
    critical: "#e5553f",
  } as Record<string, string>,
};
import { useUiStore } from "@/store/ui";

function toElements(model: GraphModel): ElementDefinition[] {
  const nodes = Object.values(model.nodes).map((n) => ({
    data: {
      id: n.id,
      label: n.kind === "attacker" ? n.label : n.label,
      kind: n.kind,
      size: nodeSize(n),
      color:
        n.kind === "core" ? C.primary : n.kind === "honeypot" ? C.honeypot : C.sev[n.severity]!,
    },
  }));
  const edges = Object.values(model.edges).map((e) => ({
    data: { id: e.id, source: e.source, target: e.target, weight: Math.min(4, 0.6 + e.events / 6) },
  }));
  return [...nodes, ...edges];
}

const STYLE = [
  {
    selector: "node",
    style: {
      "background-color": "data(color)",
      width: "data(size)",
      height: "data(size)",
      label: "data(label)",
      "font-family": "JetBrains Mono, monospace",
      "font-size": 8,
      color: C.attackerLabel,
      "text-valign": "bottom",
      "text-margin-y": 5,
      "border-width": 1,
      "border-color": C.bg,
      "text-background-opacity": 0,
      "overlay-opacity": 0,
    },
  },
  {
    selector: 'node[kind = "core"]',
    style: {
      "background-opacity": 0.16,
      "border-width": 1.5,
      "border-color": C.primary,
      color: C.primary,
      "font-size": 11,
      "font-weight": 600,
      "text-valign": "center",
      "text-wrap": "wrap",
      "text-max-width": "70px",
    },
  },
  {
    selector: 'node[kind = "honeypot"]',
    style: { shape: "round-rectangle", "font-size": 8.5, color: C.honeypotLabel },
  },
  {
    selector: "edge",
    style: {
      width: "data(weight)",
      "line-color": C.edge,
      "curve-style": "bezier",
      "target-arrow-shape": "none",
      opacity: 0.65,
    },
  },
  {
    selector: ".pulse",
    style: { "border-width": 5, "border-color": C.primary, "border-opacity": 0.75 },
  },
  {
    selector: "node:selected",
    style: { "border-width": 3, "border-color": C.primary },
  },
  {
    selector: ".dim",
    style: { opacity: 0.12 },
  },
] as unknown as cytoscape.StylesheetJson;

function runLayout(cy: Core, animate: boolean) {
  const layout = cy.layout({
    name: "cose",
    animate,
    animationDuration: 400,
    randomize: false,
    padding: 30,
    nodeRepulsion: 14000,
    idealEdgeLength: 90,
    gravity: 0.6,
    fit: true,
  } as unknown as cytoscape.LayoutOptions);
  layout.one("layoutstop", () => {
    cy.resize();
    cy.fit(undefined, 30);
  });
  layout.run();
}

export function ThreatGraph() {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const modelRef = useRef<GraphModel | null>(null);
  const { buffer } = useLiveContext();
  const selectAttacker = useUiStore((s) => s.selectAttacker);
  // The live context value changes whenever connection status changes; keep the
  // latest accessors in refs so the graph instance is created exactly once.
  const bufferRef = useRef(buffer);
  bufferRef.current = buffer;
  const selectRef = useRef(selectAttacker);
  selectRef.current = selectAttacker;
  const selectedIp = useUiStore((s) => s.selectedAttackerIp);
  const [ready, setReady] = useState(false);
  const [nodeCount, setNodeCount] = useState(0);

  useEffect(() => {
    let disposed = false;
    let cy: Core | null = null;
    let cleanup: (() => void) | undefined;

    (async () => {
      const cytoscapeLib = (await import("cytoscape")).default;
      if (disposed || !containerRef.current) return;
      // Seed from the recent buffer so the map is populated immediately.
      const model = buildGraph(bufferRef.current().slice(0, 260));
      modelRef.current = model;

      cy = cytoscapeLib({
        container: containerRef.current,
        elements: toElements(model),
        style: STYLE,
        minZoom: 0.25,
        maxZoom: 2.5,
        wheelSensitivity: 0.2,
      });
      // The container can still be laying out when cytoscape mounts, so force a
      // resize on the next frame before the first layout measures it.
      requestAnimationFrame(() => {
        cy?.resize();
        runLayout(cy!, false);
      });
      const ro = new ResizeObserver(() => {
        cy?.resize();
        cy?.fit(undefined, 30);
      });
      ro.observe(containerRef.current);
      cleanup = () => ro.disconnect();

      cy.on("tap", "node", (evt) => {
        const id = String(evt.target.id());
        selectRef.current(id.startsWith("ip:") ? id.slice(3) : null);
      });
      cy.on("tap", (evt) => {
        if (evt.target === cy) selectRef.current(null);
      });

      cyRef.current = cy;
      setNodeCount(cy.nodes().length);
      setReady(true);
    })();

    return () => {
      disposed = true;
      cleanup?.();
      cy?.destroy();
      cyRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Fold each live event into the graph and pulse whatever is new.
  useLiveEventListener((event) => {
    const cy = cyRef.current;
    const model = modelRef.current;
    if (!cy || !model) return;
    const { added, touched } = applyEvent(model, event);

    for (const id of added) {
      const isEdge = id.startsWith("e:");
      const def = toElements({
        nodes: isEdge ? {} : ({ [id]: model.nodes[id] } as Record<string, GraphNode>),
        edges: isEdge ? { [id]: model.edges[id]! } : {},
      })[0];
      if (def) cy.add(def);
    }
    for (const id of touched) {
      const el = cy.getElementById(id);
      if (!el.empty() && !id.startsWith("e:")) {
        const node = model.nodes[id];
        if (node) el.data({
          size: nodeSize(node),
          color: toElements({ nodes: { [id]: node }, edges: {} })[0]?.data["color"],
        });
        el.addClass("pulse");
        setTimeout(() => el.removeClass("pulse"), 900);
      }
    }
    if (added.length) {
      setNodeCount(cy.nodes().length);
      runLayout(cy, true);
    }
  });

  // Highlight selection coming from other surfaces (attacker table, panel).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass("dim");
    cy.nodes().unselect();
    if (!selectedIp) return;
    const node = cy.getElementById(`ip:${selectedIp}`);
    if (node.empty()) return;
    const keep = node.closedNeighborhood().union(cy.getElementById(CORE_ID));
    cy.elements().difference(keep).addClass("dim");
    node.select();
  }, [selectedIp]);

  return (
    <div className="relative h-full min-h-[320px] w-full overflow-hidden">
      <div className="grid-field absolute inset-0" />
      <div ref={containerRef} className="relative z-10 h-full w-full" />
      <div className="pointer-events-none absolute bottom-3 left-3 flex items-center gap-3 border border-border bg-background/80 px-2.5 py-1.5 backdrop-blur">
        <span className="label-caps">Nodes {nodeCount}</span>
        <span className="h-3 w-px bg-border" />
        {(["low", "medium", "high", "critical"] as const).map((s) => (
          <span key={s} className="label-caps flex items-center gap-1.5">
            <i
              className="inline-block h-1.5 w-1.5 rounded-full"
              style={{ background: SEVERITY_TOKEN[s] }}
            />
            {s}
          </span>
        ))}
      </div>
      {!ready ? (
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="label-caps animate-pulse">initializing deception graph…</span>
        </div>
      ) : null}
    </div>
  );
}

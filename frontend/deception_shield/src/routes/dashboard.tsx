import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/AppShell";
import { StatsStrip } from "@/components/StatsStrip";
import { ThreatGraph } from "@/components/ThreatGraph";
import { EventFeed } from "@/components/EventFeed";
import { AttackerDetailPanel } from "@/components/AttackerDetailPanel";
import { SectionCard } from "@/components/AppShell";
import { requireAuth } from "@/lib/authGuard";

export const Route = createFileRoute("/dashboard")({
  beforeLoad: requireAuth,
  head: () => ({
    meta: [
      { title: "Threat Console — Sentinel Deception Grid" },
      {
        name: "description",
        content:
          "Live SOC console showing attacks against deployed honeypots, attacker graph, and automated firewall responses in real time.",
      },
      { property: "og:title", content: "Threat Console — Sentinel Deception Grid" },
      {
        property: "og:description",
        content: "Real-time honeypot attack map, event feed, and automated blocking.",
      },
    ],
  }),
  component: DashboardPage,
});

import { RefreshCcw } from "lucide-react";

function DashboardPage() {
  return (
    <AppShell
      title="Threat Console"
      subtitle="Live deception telemetry across the honeypot fleet"
      actions={
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="flex items-center gap-1.5 border border-border bg-surface-raised px-2.5 py-1 text-xs text-muted-foreground hover:bg-border/50 hover:text-foreground"
          aria-label="Refresh dashboard"
        >
          <RefreshCcw className="h-3 w-3" />
          <span className="hidden sm:inline">Refresh</span>
        </button>
      }
    >
      <div className="flex min-h-0 flex-col gap-2 p-2 sm:p-3 lg:h-[calc(100vh-61px)]">
        <StatsStrip />
        <div className="grid min-h-0 flex-1 grid-cols-1 gap-2 lg:grid-cols-[1fr_340px] lg:grid-rows-[minmax(0,1fr)]">
          <div className="relative min-h-[360px] lg:min-h-0">
            <SectionCard
              title="Live Threat Map"
              aside={<span className="label-caps hidden sm:inline">force-directed · cytoscape</span>}
              className="h-full"
              bodyClassName="relative"
            >
              <ThreatGraph />
            </SectionCard>
            <AttackerDetailPanel />
          </div>
          <SectionCard
            title="Live Event Feed"
            aside={<span className="label-caps">virtualized</span>}
            className="min-h-[420px] lg:min-h-0"
          >
            <EventFeed />
          </SectionCard>
        </div>
      </div>

    </AppShell>
  );
}

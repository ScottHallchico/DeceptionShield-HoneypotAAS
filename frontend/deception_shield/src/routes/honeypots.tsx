import { createFileRoute } from "@tanstack/react-router";
import { Loader2, RefreshCw } from "lucide-react";
import { AppShell, SectionCard } from "@/components/AppShell";
import { useHoneypots, useRedeployHoneypot } from "@/api/queries";
import { relativeTime } from "@/lib/severity";
import { cn } from "@/lib/utils";
import type { HoneypotStatus } from "@/types/api";
import { requireAuth } from "@/lib/authGuard";

export const Route = createFileRoute("/honeypots")({
  beforeLoad: requireAuth,
  head: () => ({
    meta: [
      { title: "Decoy Fleet — Sentinel Deception Grid" },
      {
        name: "description",
        content:
          "Manage deployed honeypots: health, region, public address, and one-click IP rotation.",
      },
      { property: "og:title", content: "Decoy Fleet — Sentinel" },
      { property: "og:description", content: "Fleet health and IP rotation for deployed decoys." },
    ],
  }),
  component: HoneypotsPage,
});

const STATUS_STYLE: Record<HoneypotStatus, string> = {
  running: "bg-sev-low/12 text-sev-low",
  deploying: "bg-sev-medium/12 text-sev-medium",
  error: "bg-sev-critical/16 text-sev-critical",
  stopped: "bg-sev-critical/16 text-sev-critical",
};

function HoneypotsPage() {
  const { data, isLoading } = useHoneypots();
  const redeploy = useRedeployHoneypot();

  return (
    <AppShell title="Decoy Fleet" subtitle="Deployed honeypots, health, and address rotation">
      <div className="p-2 sm:p-3">
        <SectionCard title={`Instances (${data?.length ?? 0})`} bodyClassName="overflow-x-auto">
          <table className="w-full min-w-[820px] text-left">
            <thead>
              <tr className="border-b border-border">
                {["Instance", "Type", "Status", "Region", "Public address", "Uptime", ""].map((h) => (
                  <th key={h} className="label-caps px-3 py-2 font-normal">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="px-3 py-6 text-xs text-muted-foreground">
                    Querying fleet…
                  </td>
                </tr>
              ) : (
                (data ?? []).map((h) => (
                  <tr key={h.id} className="border-b border-border/60 text-xs">
                    <td className="px-3 py-3 font-mono text-[12px] text-foreground">{h.id}</td>
                    <td className="px-3 py-3 text-muted-foreground">{h.type}</td>
                    <td className="px-3 py-3">
                      <span className={cn("label-caps px-1.5 py-1", STATUS_STYLE[h.status])}>
                        {h.status}
                      </span>
                    </td>
                    <td className="px-3 py-3 font-mono text-[11px] text-muted-foreground">
                      {h.region}
                    </td>
                    <td className="mono-ip px-3 py-3">{h.ip_address}</td>
                    <td className="px-3 py-3 text-muted-foreground">
                      {relativeTime(h.deployed_at).replace(" ago", "")}
                    </td>
                    <td className="px-3 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => redeploy.mutate(h.id)}
                        disabled={redeploy.isPending && redeploy.variables === h.id}
                        className="inline-flex items-center gap-1.5 border border-border-strong px-2 py-1.5 font-mono text-[10px] tracking-[0.12em] uppercase hover:border-primary hover:text-primary disabled:opacity-50"
                      >
                        {redeploy.isPending && redeploy.variables === h.id ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <RefreshCw className="h-3 w-3" />
                        )}
                        rotate ip
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </SectionCard>
        <p className="label-caps mt-3">
          Rotation redeploys the container behind a fresh public address to defeat decoy
          fingerprinting.
        </p>
      </div>
    </AppShell>
  );
}

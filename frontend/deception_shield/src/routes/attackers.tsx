import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { AppShell, SectionCard } from "@/components/AppShell";
import { useAttackers } from "@/api/queries";
import { AttackerDetailPanel } from "@/components/AttackerDetailPanel";
import { useUiStore } from "@/store/ui";
import { SEVERITY_BG, relativeTime } from "@/lib/severity";
import { cn } from "@/lib/utils";
import type { AttackerProfile } from "@/types/api";
import { requireAuth } from "@/lib/authGuard";

export const Route = createFileRoute("/attackers")({
  beforeLoad: requireAuth,
  head: () => ({
    meta: [
      { title: "Attacker Directory — Sentinel Deception Grid" },
      {
        name: "description",
        content:
          "Aggregated attacker profiles ranked by threat score, with geo, reputation, and honeypots touched.",
      },
      { property: "og:title", content: "Attacker Directory — Sentinel" },
      { property: "og:description", content: "Every source IP that has touched the decoy fleet." },
    ],
  }),
  component: AttackersPage,
});

type SortKey = "threat_score" | "total_events" | "last_seen";

function AttackersPage() {
  const { data, isLoading } = useAttackers();
  const [sort, setSort] = useState<SortKey>("threat_score");
  const [query, setQuery] = useState("");
  const selectAttacker = useUiStore((s) => s.selectAttacker);
  const selectedIp = useUiStore((s) => s.selectedAttackerIp);

  const rows = useMemo(() => {
    const list = (data?.items ?? []).filter(
      (a) =>
        !query.trim() ||
        `${a.ip} ${a.geo?.country} ${a.geo?.org}`.toLowerCase().includes(query.trim().toLowerCase()),
    );
    return [...list].sort((a: AttackerProfile, b: AttackerProfile) =>
      sort === "last_seen" ? b.last_seen.localeCompare(a.last_seen) : b[sort] - a[sort],
    );
  }, [data, query, sort]);

  return (
    <AppShell title="Attacker Directory" subtitle="Aggregated source profiles and threat scoring">
      <div className="relative p-2 sm:p-3">
        <SectionCard
          title={`Sources (${rows.length})`}
          aside={
            <div className="flex min-w-0 items-center gap-2">
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="filter ip / org"
                className="mono-ip h-7 w-28 min-w-0 border border-input bg-surface-raised px-2 focus:border-primary focus:outline-none sm:w-48"
              />
              <select
                value={sort}
                onChange={(e) => setSort(e.target.value as SortKey)}
                className="h-7 shrink-0 border border-input bg-surface-raised px-1.5 font-mono text-[11px] focus:border-primary focus:outline-none"
              >
                <option value="threat_score">threat score</option>
                <option value="total_events">event count</option>
                <option value="last_seen">last seen</option>
              </select>
            </div>
          }

          bodyClassName="overflow-x-auto"
        >
          <table className="w-full min-w-[860px] text-left">
            <thead>
              <tr className="border-b border-border">
                {["Source IP", "Origin", "Network", "Events", "Honeypots", "Reputation", "Status", "Threat", "Last seen"].map(
                  (h) => (
                    <th key={h} className="label-caps px-3 py-2 font-normal">
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={9} className="px-3 py-6 text-xs text-muted-foreground">
                    Aggregating attacker profiles…
                  </td>
                </tr>
              ) : (
                rows.map((a) => (
                  <tr
                    key={a.ip}
                    onClick={() => selectAttacker(a.ip)}
                    className={cn(
                      "cursor-pointer border-b border-border/60 text-xs hover:bg-surface-raised",
                      selectedIp === a.ip && "bg-surface-raised",
                    )}
                  >
                    <td className="mono-ip px-3 py-2.5 text-foreground">{a.ip}</td>
                    <td className="px-3 py-2.5 text-muted-foreground">
                      {[a.geo.city, a.geo.country].filter(Boolean).join(", ") || "Unknown"}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[11px] text-muted-foreground">
                      {a.geo.asn || "Unknown"}
                    </td>
                    <td className="px-3 py-2.5 font-mono tabular-nums">{a.total_events}</td>
                    <td className="px-3 py-2.5 font-mono text-[11px] text-muted-foreground">
                      {a.honeypots_hit.length}
                    </td>
                    <td className="px-3 py-2.5 font-mono tabular-nums">
                      {a.reputation.abuseipdb_score}
                    </td>
                    <td className="px-3 py-2.5">
                      <span
                        className={cn(
                          "label-caps px-1.5 py-1",
                          a.is_blocked
                            ? SEVERITY_BG.critical
                            : SEVERITY_BG.low,
                        )}
                      >
                        {a.is_blocked ? "blocked" : "clear"}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-2">
                        <div className="h-1 w-16 bg-border">
                          <div
                            className="h-full bg-primary"
                            style={{ width: `${a.threat_score}%` }}
                          />
                        </div>
                        <span className="font-mono text-[11px] tabular-nums">{a.threat_score}</span>
                      </div>
                    </td>
                    <td className="px-3 py-2.5 text-muted-foreground">
                      {relativeTime(a.last_seen)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </SectionCard>
        <AttackerDetailPanel />
        <p className="label-caps mt-3">
          Tip: sessions for a source are linked inside its profile panel ·{" "}
          <Link to="/dashboard" className="text-primary hover:underline">
            back to live map
          </Link>
        </p>
      </div>
    </AppShell>
  );
}

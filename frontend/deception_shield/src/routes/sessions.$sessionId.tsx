import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { AppShell, SectionCard } from "@/components/AppShell";
import { SessionPlayer } from "@/components/SessionPlayer";
import { useSession } from "@/api/queries";
import { SEVERITY_BG, formatTime } from "@/lib/severity";
import { cn } from "@/lib/utils";
import { requireAuth } from "@/lib/authGuard";

export const Route = createFileRoute("/sessions/$sessionId")({
  beforeLoad: requireAuth,
  head: () => ({
    meta: [
      { title: "Session Replay — Sentinel Deception Grid" },
      {
        name: "description",
        content:
          "Scrubbable replay of a captured attacker shell session inside the honeypot, keystroke by keystroke.",
      },
      { property: "og:title", content: "Session Replay — Sentinel" },
      {
        property: "og:description",
        content: "Watch exactly what an intruder typed inside the decoy shell.",
      },
    ],
  }),
  component: SessionPage,
});

function SessionPage() {
  const { sessionId } = Route.useParams();
  const { data, isLoading } = useSession(sessionId);

  return (
    <AppShell
      title="Attack Session Replay"
      subtitle={`session ${sessionId}`}
      actions={
        <Link
          to="/dashboard"
          className="label-caps flex items-center gap-1.5 border border-border bg-surface-raised px-2 py-1.5 hover:text-foreground"
        >
          <ArrowLeft className="h-3 w-3" /> console
        </Link>
      }
    >
      <div className="grid min-h-0 grid-cols-1 gap-2 p-2 sm:p-3 lg:h-[calc(100vh-61px)] lg:grid-cols-[1fr_320px]">
        <SectionCard
          title="TTY playback"
          aside={<span className="label-caps">{data?.honeypot_type ?? "…"}</span>}
          className="min-h-0"
        >
          {isLoading ? (
            <p className="p-4 text-xs text-muted-foreground">Loading capture…</p>
          ) : (
            <SessionPlayer frames={data?.tty_log ? JSON.parse(data.tty_log) : []} />
          )}
        </SectionCard>

        <div className="flex min-h-0 flex-col gap-2">
          <SectionCard title="Session metadata">
            <dl className="px-4 py-2">
              {[
                ["Source IP", data?.attacker_ip ?? "—"],
                ["Honeypot", data?.honeypot_id ?? "—"],
                ["Origin", data?.events[0] ? `${data.events[0].geo.city}, ${data.events[0].geo.country}` : "—"],
                ["Network", data?.events[0] ? `${data.events[0].geo.asn} · ${data.events[0].geo.org}` : "—"],
                ["Started", data ? formatTime(data.started_at) : "—"],
                ["Ended", data ? formatTime(data.ended_at) : "—"],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between gap-3 border-b border-border/60 py-2">
                  <dt className="label-caps">{k}</dt>
                  <dd className="truncate font-mono text-[11px] text-foreground">{v}</dd>
                </div>
              ))}
            </dl>
          </SectionCard>

          <SectionCard title={`Events in session (${data?.events.length ?? 0})`} className="min-h-0" bodyClassName="overflow-y-auto">
            <ul className="divide-y divide-border/60">
              {(data?.events ?? []).map((e) => (
                <li key={e.id} className="px-4 py-2.5">
                  <div className="flex items-center gap-2">
                    <span className={cn("label-caps px-1 py-0.5", SEVERITY_BG[e.severity])}>
                      {e.severity}
                    </span>
                    <span className="label-caps">{e.event_type}</span>
                    <span className="label-caps ml-auto">{formatTime(e.timestamp)}</span>
                  </div>
                  <p className="mt-1.5 truncate font-mono text-[11px] text-muted-foreground">
                    {e.payload}
                  </p>
                </li>
              ))}
            </ul>
          </SectionCard>
        </div>
      </div>
    </AppShell>
  );
}

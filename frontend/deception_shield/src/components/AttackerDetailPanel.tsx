import { Link } from "@tanstack/react-router";
import { ExternalLink, X } from "lucide-react";
import { useAttackers } from "@/api/queries";
import { useUiStore } from "@/store/ui";
import { SEVERITY_BG, relativeTime } from "@/lib/severity";
import { cn } from "@/lib/utils";

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/60 py-2">
      <span className="label-caps">{label}</span>
      <span className={cn("truncate text-right text-xs text-foreground", mono && "font-mono")}>
        {value}
      </span>
    </div>
  );
}

export function AttackerDetailPanel() {
  const selectedIp = useUiStore((s) => s.selectedAttackerIp);
  const selectAttacker = useUiStore((s) => s.selectAttacker);
  const { data: attackers } = useAttackers();
  if (!selectedIp) return null;

  const profile = attackers?.items?.find((a) => a.ip === selectedIp);

  return (
    <aside
      data-testid="attacker-panel"
      className="panel absolute inset-x-2 inset-y-2 z-30 flex flex-col overflow-hidden sm:inset-x-auto sm:inset-y-3 sm:right-3 sm:w-[320px]"
    >
      <header className="flex items-start justify-between gap-2 border-b border-border px-4 py-3">
        <div className="min-w-0">
          <div className="label-caps">Attacker profile</div>
          <div className="mono-ip mt-1 truncate text-[15px] text-foreground">{selectedIp}</div>
        </div>
        <button
          type="button"
          aria-label="Close attacker panel"
          onClick={() => selectAttacker(null)}
          className="text-muted-foreground hover:text-foreground"
        >
          <X className="h-4 w-4" />
        </button>
      </header>

      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-2">
        {!profile ? (
          <p className="py-6 text-xs text-muted-foreground">
            Aggregating profile for this source…
          </p>
        ) : (
          <>
            <div className="flex items-center gap-2 py-2">
              <span
                className={cn(
                  "label-caps px-1.5 py-1",
                  profile.is_blocked
                    ? SEVERITY_BG.critical
                    : SEVERITY_BG.low,
                )}
              >
                {profile.is_blocked ? "blocked" : "clear"}
              </span>
              <span className="label-caps">threat {profile.threat_score}/100</span>
            </div>

            <Field label="Location" value={`${profile.geo.city}, ${profile.geo.country}`} />
            <Field label="Network" value={`${profile.geo.asn} · ${profile.geo.org}`} mono />
            <Field label="AbuseIPDB" value={`${profile.reputation.abuseipdb_score}/100`} mono />
            <Field
              label="Known malicious"
              value={profile.reputation.known_malicious ? "yes" : "no"}
            />
            <Field label="First seen" value={relativeTime(profile.first_seen)} />
            <Field label="Last seen" value={relativeTime(profile.last_seen)} />
            <Field label="Total events" value={String(profile.total_events)} mono />

            <div className="mt-4">
              <div className="label-caps">Techniques</div>
              <div className="mt-1.5 flex flex-wrap gap-1">
                {profile.techniques_used.map((t) => (
                  <span key={t} className="label-caps border border-border bg-surface-raised px-1.5 py-1">
                    {t.replace(/_/g, " ")}
                  </span>
                ))}
              </div>
            </div>

            <div className="mt-4">
              <div className="label-caps">Honeypots touched</div>
              <ul className="mt-1.5 space-y-1">
                {profile.honeypots_hit.map((h) => (
                  <li key={h} className="font-mono text-[11px] text-foreground">
                    {h}
                  </li>
                ))}
              </ul>
            </div>

            {profile.sessions && profile.sessions.length > 0 && (
              <div className="mt-4">
                <div className="label-caps">Sessions</div>
                <ul className="mt-1.5 space-y-1">
                  {profile.sessions.map((s) => (
                    <li key={s}>
                      <Link
                        to="/sessions/$sessionId"
                        params={{ sessionId: s }}
                        className="flex items-center gap-1 font-mono text-[11px] text-primary hover:underline"
                      >
                        <ExternalLink className="h-3 w-3" />
                        {s.split("-")[0]}...
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </div>
    </aside>
  );
}

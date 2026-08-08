import { useEffect, useMemo, useState } from "react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useHeartbeat, useLiveEvents } from "@/hooks/useLiveEvents";
import { useStats } from "@/api/queries";
import { cn } from "@/lib/utils";

function Metric({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: string;
  hint?: string;
  tone?: "default" | "alert" | "primary";
}) {
  return (
    <div className="panel min-w-0 flex-1 px-3 py-2.5 sm:min-w-[150px] sm:px-4 sm:py-3">
      <div className="label-caps">{label}</div>
      <div
        className={cn(
          "mt-2 font-mono text-2xl leading-none tracking-tight tabular-nums",
          tone === "alert" && "text-sev-critical",
          tone === "primary" && "text-primary",
        )}
      >
        {value}
      </div>
      {hint ? <div className="mt-1.5 text-[11px] text-muted-foreground">{hint}</div> : null}
    </div>
  );
}

export function StatsStrip() {
  const hb = useHeartbeat();
  const { data: stats } = useStats();
  const { events } = useLiveEvents({ limit: 900 });
  const [flash, setFlash] = useState(false);

  useEffect(() => {
    setFlash(true);
    const t = setTimeout(() => setFlash(false), 400);
    return () => clearTimeout(t);
  }, [events.length]);

  const derived = useMemo(() => {
    const dayAgo = Date.now() - 86_400_000;
    const today = events.filter((e) => Date.parse(e.timestamp) > dayAgo);
    return {
      attacks: hb?.total_events_24h ?? today.length,
      attackers: new Set(today.map((e) => e.attacker_ip)).size,
      blocked: hb?.active_blocks ?? 0,
      critical: today.filter((e) => e.severity === "critical").length,
    };
  }, [events, hb]);

  const spark = (stats?.attack_timeline ?? []).map((p) => ({
    t: new Date(p.timestamp).getHours(),
    count: p.count,
  }));

  return (
    <div className="grid grid-cols-2 items-stretch gap-2 sm:flex sm:flex-wrap">
      <Metric
        label="Attacks / 24h"
        value={derived.attacks.toLocaleString()}
        hint={flash ? "ingesting…" : "normalized + enriched"}
      />
      <Metric label="Distinct attackers" value={String(derived.attackers)} hint="active sources" />
      <Metric label="IPs blocked" value={String(derived.blocked)} tone="alert" hint="firewall enforced" />
      <Metric
        label="Critical events"
        value={String(derived.critical)}
        tone="primary"
        hint="payload drop / CVE"
      />
      <div className="panel col-span-2 min-w-0 px-3 py-2.5 sm:min-w-[240px] sm:flex-[2] sm:px-4 sm:py-3">
        <div className="flex items-center justify-between">
          <span className="label-caps">Attacks / hour</span>
          <span className="label-caps">24h</span>
        </div>
        <div className="mt-2 h-[46px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={spark} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="sparkFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.42} />
                  <stop offset="100%" stopColor="var(--primary)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="t" hide />
              <YAxis hide />
              <Tooltip
                contentStyle={{
                  background: "var(--popover)",
                  border: "1px solid var(--border-strong)",
                  borderRadius: 2,
                  fontSize: 11,
                  fontFamily: "var(--font-mono)",
                }}
                labelFormatter={(h) => `${String(h).padStart(2, "0")}:00`}
              />
              <Area
                type="monotone"
                dataKey="count"
                stroke="var(--primary)"
                strokeWidth={1.5}
                fill="url(#sparkFill)"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

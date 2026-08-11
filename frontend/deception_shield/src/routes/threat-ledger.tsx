import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { Loader2, Search, Shield, ShieldCheck, Zap, Globe2, Hash, Database, Waypoints } from "lucide-react";
import { AppShell, SectionCard } from "@/components/AppShell";
import { useMidnightStats, useMidnightQuery } from "@/api/queries";
import { requireAuth } from "@/lib/authGuard";

export const Route = createFileRoute("/threat-ledger")({
  beforeLoad: requireAuth,
  head: () => ({
    meta: [
      { title: "Collective Threat Intelligence — Sentinel Deception Grid" },
      {
        name: "description",
        content:
          "Privacy-preserving collective defense ledger powered by Midnight blockchain. View network-wide attestations and corroboration counts.",
      },
      { property: "og:title", content: "Collective Threat Intelligence — Sentinel" },
      {
        property: "og:description",
        content: "Midnight-powered ZK threat intelligence across the DeceptionShield network.",
      },
    ],
  }),
  component: ThreatLedgerPage,
});

function AnimatedCounter({ value, label, icon: Icon, accent }: {
  value: number;
  label: string;
  icon: typeof Shield;
  accent?: string;
}) {
  return (
    <div className="panel flex flex-col items-center justify-center gap-2 px-6 py-5 midnight-glow">
      <Icon
        className="h-5 w-5"
        style={{ color: accent || "var(--midnight-purple)" }}
        strokeWidth={1.75}
      />
      <div
        className="font-mono text-2xl font-bold tabular-nums tracking-tight"
        style={{ color: accent || "var(--midnight-purple)" }}
      >
        {value.toLocaleString()}
      </div>
      <div className="label-caps text-center">{label}</div>
    </div>
  );
}

function NetworkVisualization() {
  const [activeNodes, setActiveNodes] = useState<number[]>([]);

  useEffect(() => {
    const interval = setInterval(() => {
      const active = [];
      const numActive = Math.floor(Math.random() * 3) + 1;
      for (let i = 0; i < numActive; i++) {
        active.push(Math.floor(Math.random() * 5));
      }
      setActiveNodes(active);
    }, 2500);
    return () => clearInterval(interval);
  }, []);

  const nodes = [
    { id: 0, label: "Your Honeypot", x: 20, y: 20, isSelf: true },
    { id: 1, label: "Anonymous Peer", x: 80, y: 15, isSelf: false },
    { id: 2, label: "Anonymous Peer", x: 15, y: 80, isSelf: false },
    { id: 3, label: "Anonymous Peer", x: 85, y: 75, isSelf: false },
    { id: 4, label: "Anonymous Peer", x: 50, y: 85, isSelf: false },
  ];

  return (
    <SectionCard title="Live Network Corroboration" aside={<span className="label-caps text-[var(--midnight-purple)]">ZK proofs in transit</span>}>
      <div className="relative h-72 bg-[#050505] overflow-hidden border-b border-border">
        {/* SVG Lines */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          <defs>
            <linearGradient id="active-line" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="var(--midnight-purple)" />
              <stop offset="100%" stopColor="var(--midnight-verified)" />
            </linearGradient>
          </defs>
          {nodes.map(node => {
            const isActive = activeNodes.includes(node.id);
            return (
              <line
                key={node.id}
                x1={`${node.x}%`} y1={`${node.y}%`}
                x2="50%" y2="50%"
                stroke={isActive ? "url(#active-line)" : "rgba(255,255,255,0.05)"}
                strokeWidth={isActive ? 2 : 1}
                className="transition-all duration-1000"
              />
            );
          })}
        </svg>

        {/* Nodes */}
        {nodes.map(node => {
          const isActive = activeNodes.includes(node.id);
          return (
            <div
              key={node.id}
              className="absolute -translate-x-1/2 -translate-y-1/2 flex flex-col items-center"
              style={{ left: `${node.x}%`, top: `${node.y}%` }}
            >
              <div className={`h-10 w-10 rounded-full border flex items-center justify-center relative ${node.isSelf ? 'border-primary/50 bg-primary/10' : 'border-border-strong bg-surface'}`}>
                {node.isSelf ? (
                  <Database className="h-4 w-4 text-primary" />
                ) : (
                  <Shield className="h-4 w-4 text-muted-foreground" />
                )}
                {isActive && (
                   <div className="absolute inset-0 rounded-full border border-[var(--midnight-purple)] animate-ping opacity-50" />
                )}
              </div>
              <div className="mt-1.5 text-[10px] font-mono tracking-tight text-muted-foreground bg-[#050505]/80 px-1 rounded">{node.label}</div>
            </div>
          );
        })}

        {/* Central Ledger Node */}
        <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center">
          <div className="h-16 w-16 border border-[var(--midnight-verified)]/50 bg-[var(--midnight-verified)]/10 rounded-lg flex items-center justify-center shadow-[0_0_30px_rgba(33,212,176,0.15)] relative">
            <div className="absolute inset-0 bg-[var(--midnight-verified)]/20 animate-pulse rounded-lg" />
            <Waypoints className="h-7 w-7 text-[var(--midnight-verified)] relative z-10" />
          </div>
          <div className="mt-2 text-xs font-semibold text-white bg-[#050505]/80 px-2 py-0.5 rounded">Midnight Ledger</div>
          <div className="text-[10px] text-[var(--midnight-verified)] font-mono bg-[#050505]/80 px-1 rounded">Global State</div>
        </div>
      </div>
    </SectionCard>
  );
}

function ThreatLedgerPage() {
  const { data: stats, isLoading: statsLoading } = useMidnightStats();
  const [lookupIp, setLookupIp] = useState("");
  const [submittedIp, setSubmittedIp] = useState("");
  const { data: queryResult, isLoading: queryLoading } = useMidnightQuery(submittedIp);

  const handleLookup = (e: React.FormEvent) => {
    e.preventDefault();
    if (lookupIp.trim()) setSubmittedIp(lookupIp.trim());
  };

  return (
    <AppShell
      title="Collective Threat Intelligence"
      subtitle="Privacy-preserving threat corroboration powered by Midnight"
    >
      <div className="space-y-2 p-2 sm:space-y-3 sm:p-3">
        {/* Network Overview Stats */}
        <SectionCard
          title="Network Overview"
          aside={
            <div className="flex items-center gap-3">
              <button
                onClick={async () => {
                  const { api } = await import("@/api/client");
                  await api.simulateEvent();
                  alert("Critical event simulated! Check the blocklist to see the result and the Midnight attestation.");
                }}
                className="inline-flex h-6 items-center gap-1.5 border border-red-500/50 bg-red-500/10 px-2 font-mono text-[10px] tracking-[0.12em] text-red-500 uppercase hover:bg-red-500/20"
              >
                <Zap className="h-3 w-3" />
                Simulate Attack
              </button>
              <span className="verified-badge">
                <ShieldCheck className="h-3 w-3" />
                midnight verified
              </span>
            </div>
          }
        >
          <div className="p-4">
            {/* Status Banner */}
            <div className="mb-4 flex items-center gap-3 border border-[var(--midnight-purple)]/20 bg-[var(--midnight-purple)]/5 px-4 py-3">
              <div className="relative flex h-2 w-2">
                <span
                  className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-70"
                  style={{ backgroundColor: "var(--midnight-verified)" }}
                />
                <span
                  className="relative inline-flex h-2 w-2 rounded-full"
                  style={{ backgroundColor: "var(--midnight-verified)" }}
                />
              </div>
              <span className="text-xs" style={{ color: "var(--midnight-verified)" }}>
                {stats?.networkMode === "simulate"
                  ? "Connected to local devnet (simulation mode)"
                  : stats?.networkMode === "disabled"
                    ? "Midnight integration disabled"
                    : `Connected to ${stats?.networkMode ?? "unknown"} network`}
              </span>
            </div>

            {statsLoading ? (
              <div className="flex items-center justify-center gap-2 py-8 text-xs text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                Querying ledger state…
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <AnimatedCounter
                  value={stats?.totalAttestations ?? 0}
                  label="Total Attestations"
                  icon={Zap}
                  accent="var(--midnight-purple)"
                />
                <AnimatedCounter
                  value={stats?.uniqueIndicators ?? 0}
                  label="Unique Indicators"
                  icon={Globe2}
                  accent="var(--primary)"
                />
                <AnimatedCounter
                  value={stats?.totalAttestations && stats?.uniqueIndicators
                    ? Math.round(stats.totalAttestations / Math.max(stats.uniqueIndicators, 1) * 10) / 10
                    : 0}
                  label="Avg Corroboration"
                  icon={Shield}
                  accent="var(--midnight-verified)"
                />
              </div>
            )}
          </div>
        </SectionCard>

        {/* Network Graph */}
        <NetworkVisualization />

        {/* How It Works */}
        <SectionCard
          title="How Selective Disclosure Protects Participants"
          aside={<span className="label-caps">zero-knowledge proofs</span>}
        >
          <div className="grid grid-cols-1 gap-px border-t border-border sm:grid-cols-3">
            <div className="border-b border-border/60 px-4 py-3 sm:border-b-0 sm:border-r">
              <div className="label-caps mb-2 !text-[var(--midnight-verified)]">public (on-chain)</div>
              <ul className="space-y-1.5 text-xs text-muted-foreground">
                <li className="flex items-start gap-1.5">
                  <Hash className="mt-0.5 h-3 w-3 shrink-0" style={{ color: "var(--midnight-verified)" }} />
                  Anonymized indicator hash
                </li>
                <li className="flex items-start gap-1.5">
                  <Hash className="mt-0.5 h-3 w-3 shrink-0" style={{ color: "var(--midnight-verified)" }} />
                  MITRE technique category
                </li>
                <li className="flex items-start gap-1.5">
                  <Hash className="mt-0.5 h-3 w-3 shrink-0" style={{ color: "var(--midnight-verified)" }} />
                  Corroboration counter
                </li>
              </ul>
            </div>
            <div className="border-b border-border/60 px-4 py-3 sm:border-b-0 sm:border-r">
              <div className="label-caps mb-2 !text-[var(--midnight-purple)]">private (zk witness)</div>
              <ul className="space-y-1.5 text-xs text-muted-foreground">
                <li>Submitting organization identity</li>
                <li>Exact severity score</li>
                <li>Honeypot / network details</li>
              </ul>
            </div>
            <div className="px-4 py-3">
              <div className="label-caps mb-2 !text-[var(--sev-medium)]">proven predicate</div>
              <p className="text-xs text-muted-foreground">
                "This submission's severity score is above the high-confidence threshold"
                — disclosed as a boolean, not the number. Two SMBs corroborating the
                same attacker never learn anything about each other.
              </p>
            </div>
          </div>
        </SectionCard>

        {/* Indicator Lookup */}
        <SectionCard
          title="Indicator Lookup"
          aside={<span className="label-caps">query the collective defense ledger</span>}
        >
          <div className="p-4">
            <form onSubmit={handleLookup} className="flex items-end gap-3">
              <label className="flex flex-1 flex-col gap-1">
                <span className="label-caps">attacker ip address</span>
                <input
                  type="text"
                  placeholder="e.g. 203.0.113.45"
                  value={lookupIp}
                  onChange={(e) => setLookupIp(e.target.value)}
                  className="h-8 border border-input bg-surface-raised px-3 font-mono text-xs focus:border-primary focus:outline-none"
                />
              </label>
              <button
                type="submit"
                disabled={!lookupIp.trim() || queryLoading}
                className="inline-flex h-8 items-center gap-1.5 border border-border-strong px-3 font-mono text-[10px] tracking-[0.12em] uppercase hover:border-[var(--midnight-purple)] hover:text-[var(--midnight-purple)] disabled:opacity-40"
              >
                {queryLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Search className="h-3 w-3" />}
                query
              </button>
            </form>

            {queryResult && (
              <div className="mt-4 border border-border bg-surface-raised p-4">
                <div className="mb-3 flex items-center gap-2">
                  <span className="mono-ip text-foreground">{queryResult.ip}</span>
                  {queryResult.corroborationCount > 0 && (
                    <span className="verified-badge">
                      <ShieldCheck className="h-3 w-3" />
                      corroborated
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="label-caps mb-1">independent corroborations</div>
                    <div
                      className="font-mono text-xl font-bold tabular-nums"
                      style={{
                        color: queryResult.corroborationCount > 0
                          ? "var(--midnight-verified)"
                          : "var(--muted-foreground)",
                      }}
                    >
                      {queryResult.corroborationCount}
                    </div>
                  </div>
                  <div>
                    <div className="label-caps mb-1">high-confidence</div>
                    <div
                      className="font-mono text-xl font-bold tabular-nums"
                      style={{
                        color: queryResult.highConfidenceCount > 0
                          ? "var(--midnight-purple)"
                          : "var(--muted-foreground)",
                      }}
                    >
                      {queryResult.highConfidenceCount}
                    </div>
                  </div>
                </div>
                {queryResult.corroborationCount > 0 && (
                  <p className="mt-3 text-xs text-muted-foreground">
                    This indicator has been independently attested by{" "}
                    <strong className="text-foreground">{queryResult.corroborationCount}</strong>{" "}
                    deployment{queryResult.corroborationCount === 1 ? "" : "s"} across the network,
                    with {queryResult.highConfidenceCount} high-confidence attestation{queryResult.highConfidenceCount === 1 ? "" : "s"}.
                    This corroboration lowers the blocking threshold by 30% for this indicator.
                  </p>
                )}
                {queryResult.corroborationCount === 0 && (
                  <p className="mt-3 text-xs text-muted-foreground">
                    No independent attestations found for this indicator. It has not been
                    reported by any other deployment in the network.
                  </p>
                )}
              </div>
            )}
          </div>
        </SectionCard>

        {/* Contract Info */}
        <SectionCard
          title="Contract Information"
          aside={<span className="label-caps">midnight blockchain</span>}
        >
          <div className="grid grid-cols-1 gap-px border-t border-border sm:grid-cols-2">
            <div className="border-b border-border/60 px-4 py-3 sm:border-b-0 sm:border-r">
              <div className="label-caps mb-1">contract</div>
              <div className="font-mono text-xs text-foreground">defense_ledger.compact</div>
            </div>
            <div className="px-4 py-3">
              <div className="label-caps mb-1">network</div>
              <div className="font-mono text-xs text-foreground">
                {stats?.networkMode === "simulate" ? "Local Devnet (Simulation)" : stats?.networkMode ?? "Unknown"}
              </div>
            </div>
          </div>
        </SectionCard>
      </div>
    </AppShell>
  );
}

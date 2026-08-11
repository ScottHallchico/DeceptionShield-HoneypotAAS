import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Loader2, ShieldCheck, ShieldOff } from "lucide-react";
import { AppShell, SectionCard } from "@/components/AppShell";
import { useBlocklist, useRules, useUnblockIp, useUpdateRule } from "@/api/queries";
import { countdown, relativeTime } from "@/lib/severity";
import type { ResponseRule } from "@/types/api";
import { requireAuth } from "@/lib/authGuard";

export const Route = createFileRoute("/blocklist")({
  beforeLoad: requireAuth,
  head: () => ({
    meta: [
      { title: "Blocklist & Response — Sentinel Deception Grid" },
      {
        name: "description",
        content:
          "Currently blocked attacker IPs with triggering rule, expiry countdown, firewall action, and editable response thresholds.",
      },
      { property: "og:title", content: "Blocklist & Response — Sentinel" },
      {
        property: "og:description",
        content: "Automated firewall blocks and threshold rule editor.",
      },
    ],
  }),
  component: BlocklistPage,
});

function useTick(ms = 1000) {
  const [, set] = useState(0);
  useEffect(() => {
    const id = setInterval(() => set((n) => n + 1), ms);
    return () => clearInterval(id);
  }, [ms]);
}

function RuleRow({ rule }: { rule: ResponseRule }) {
  const [draft, setDraft] = useState(rule);
  const update = useUpdateRule();
  const dirty = JSON.stringify(draft) !== JSON.stringify(rule);

  useEffect(() => setDraft(rule), [rule]);

  const num = (key: "threshold_count" | "threshold_window_seconds" | "block_duration_hours", label: string) => (
    <label className="flex flex-col gap-1">
      <span className="label-caps">{label}</span>
      <input
        type="number"
        min={1}
        value={draft[key]}
        onChange={(e) => setDraft({ ...draft, [key]: Number(e.target.value) })}
        className="h-7 w-20 border border-input bg-surface-raised px-2 font-mono text-[11px] tabular-nums focus:border-primary focus:outline-none"
      />
    </label>
  );

  const text = (key: "description" | "honeypot_type" | "severity_filter", label: string, placeholder?: string) => (
    <label className="flex flex-col gap-1">
      <span className="label-caps">{label}</span>
      <input
        type="text"
        placeholder={placeholder}
        value={draft[key] ?? ""}
        onChange={(e) => setDraft({ ...draft, [key]: e.target.value || undefined })}
        className="h-7 w-28 border border-input bg-surface-raised px-2 font-mono text-[11px] focus:border-primary focus:outline-none"
      />
    </label>
  );

  return (
    <div className="flex flex-col gap-3 border-b border-border/60 px-4 py-3">
      <div className="flex flex-wrap items-end gap-4">
        <div className="min-w-[190px] flex-1">
        <div className="text-xs font-medium text-foreground">{rule.name}</div>
        <div className="label-caps mt-1">{rule.event_type}</div>
      </div>
        {num("threshold_count", "events")}
        {num("threshold_window_seconds", "within (s)")}
        {num("block_duration_hours", "block (h)")}
        <label className="flex flex-col gap-1">
          <span className="label-caps">enabled</span>
        <button
          type="button"
          role="switch"
          aria-checked={draft.is_enabled}
          onClick={() => setDraft({ ...draft, is_enabled: !draft.is_enabled })}
          className={
            "h-7 w-14 border font-mono text-[10px] tracking-[0.12em] uppercase " +
            (draft.is_enabled
              ? "border-primary/50 bg-primary/12 text-primary"
              : "border-border text-muted-foreground")
          }
        >
          {draft.is_enabled ? "on" : "off"}
        </button>
      </label>
        <button
          type="button"
          disabled={!dirty || update.isPending}
          onClick={() => update.mutate(draft)}
          className="inline-flex h-7 items-center gap-1.5 border border-border-strong px-2.5 font-mono text-[10px] tracking-[0.12em] uppercase hover:border-primary hover:text-primary disabled:opacity-40"
        >
          {update.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
          save
        </button>
      </div>
      <div className="flex flex-wrap items-end gap-4">
        {text("description", "description", "rule description...")}
        {text("honeypot_type", "honeypot type", "e.g. rdp")}
        {text("severity_filter", "severity filter", "e.g. critical")}
      </div>
    </div>
  );
}

function BlocklistPage() {
  useTick();
  const { data: blocks, isLoading } = useBlocklist();
  const { data: rules } = useRules();
  const unblock = useUnblockIp();

  return (
    <AppShell
      title="Blocklist & Response"
      subtitle="Enforced firewall denials and the rules that produced them"
    >
      <div className="space-y-2 p-2 sm:space-y-3 sm:p-3">
        <SectionCard
          title={`Active blocks (${blocks?.items?.length ?? 0})`}
          aside={<span className="label-caps">aws sg · pfsense</span>}
          bodyClassName="overflow-x-auto"
        >
          <table className="w-full min-w-[880px] text-left">
            <thead>
              <tr className="border-b border-border">
                {["IP", "Blocked", "Expires in", "Rule triggered", "Reason", "Action taken", "Midnight", ""].map(
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
                  <td colSpan={8} className="px-3 py-6 text-xs text-muted-foreground">
                    Reading firewall state…
                  </td>
                </tr>
              ) : blocks?.items?.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-3 py-6 text-xs text-muted-foreground">
                    No IPs are currently blocked.
                  </td>
                </tr>
              ) : (
                (blocks?.items ?? []).map((b) => (
                  <tr key={b.ip} className="border-b border-border/60 text-xs">
                    <td className="mono-ip px-3 py-3 text-foreground">{b.ip}</td>
                    <td className="px-3 py-3 text-muted-foreground">{relativeTime(b.blocked_at)}</td>
                    <td className="px-3 py-3 font-mono tabular-nums text-sev-medium">
                      {countdown(b.expires_at)}
                    </td>
                    <td className="px-3 py-3 text-muted-foreground">{b.rule_triggered}</td>
                    <td className="px-3 py-3 text-muted-foreground">{b.reason}</td>
                    <td className="px-3 py-3 font-mono text-[11px]">{b.action_taken}</td>
                    <td className="px-3 py-3 text-right">
                      {b.midnight_attestation_status === "confirmed" ? (
                        <div className="flex flex-col items-end gap-1">
                          <span className="verified-badge">
                            <ShieldCheck className="h-3 w-3" /> verified
                          </span>
                          {b.midnight_tx_hash && (
                            <a
                              href={`https://explorer.midnight.network/tx/${b.midnight_tx_hash}`}
                              target="_blank"
                              rel="noreferrer"
                              className="text-[10px] text-[var(--midnight-verified)] hover:underline opacity-80"
                            >
                              view tx ↗
                            </a>
                          )}
                        </div>
                      ) : b.midnight_attestation_status === "pending" ? (
                        <span className="label-caps text-sev-medium">pending…</span>
                      ) : b.midnight_attestation_status === "failed" ? (
                        <span className="label-caps text-sev-critical">failed</span>
                      ) : (
                        <span className="label-caps">—</span>
                      )}
                    </td>
                    <td className="px-3 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => unblock.mutate(b.ip)}
                        disabled={unblock.isPending && unblock.variables === b.ip}
                        className="inline-flex items-center gap-1.5 border border-border-strong px-2 py-1.5 font-mono text-[10px] tracking-[0.12em] uppercase hover:border-sev-critical hover:text-sev-critical disabled:opacity-50"
                      >
                        <ShieldOff className="h-3 w-3" /> unblock
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </SectionCard>

        <SectionCard
          title="Response rule editor"
          aside={<span className="label-caps">applied live · no redeploy</span>}
        >
          {(rules ?? []).map((r) => (
            <RuleRow key={r.id} rule={r} />
          ))}
        </SectionCard>
      </div>
    </AppShell>
  );
}

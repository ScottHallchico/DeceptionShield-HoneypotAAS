import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Check, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { AppShell, SectionCard } from "@/components/AppShell";
import { requireAuth } from "@/lib/authGuard";

export const Route = createFileRoute("/settings")({
  beforeLoad: requireAuth,
  head: () => ({
    meta: [
      { title: "Settings — Sentinel Deception Grid" },
      {
        name: "description",
        content:
          "Configure alert channels, IP allowlist, and write-only firewall credentials for the deception network.",
      },
      { property: "og:title", content: "Settings — Sentinel" },
      { property: "og:description", content: "Alerting, allowlist, and credential configuration." },
    ],
  }),
  component: SettingsPage,
});

function CredentialField({ label, hint }: { label: string; hint: string }) {
  const [value, setValue] = useState("");
  const [configured, setConfigured] = useState(label.includes("AWS"));

  return (
    <div className="border-b border-border/60 py-3">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-xs font-medium text-foreground">{label}</div>
          <div className="label-caps mt-1">{hint}</div>
        </div>
        {configured ? (
          <span className="label-caps flex items-center gap-1 bg-sev-low/12 px-2 py-1 !text-sev-low">
            <Check className="h-3 w-3" /> configured
          </span>
        ) : null}
      </div>
      <div className="mt-2 flex gap-2">
        <input
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={configured ? "•••••••••••• (write-only)" : "paste secret"}
          className="mono-ip h-8 flex-1 border border-input bg-surface-raised px-2 focus:border-primary focus:outline-none"
        />
        <button
          type="button"
          disabled={!value}
          onClick={() => {
            setConfigured(true);
            setValue("");
            toast.success(`${label} stored`, { description: "Value is write-only and never returned." });
          }}
          className="h-8 border border-border-strong px-3 font-mono text-[10px] tracking-[0.12em] uppercase hover:border-primary hover:text-primary disabled:opacity-40"
        >
          save
        </button>
      </div>
    </div>
  );
}

function SettingsPage() {
  const [slack, setSlack] = useState("");
  const [emailTo, setEmailTo] = useState("soc@acme-plumbing.co");
  const [allowlist, setAllowlist] = useState(["203.0.113.24", "198.51.100.7"]);
  const [newIp, setNewIp] = useState("");

  return (
    <AppShell title="Settings" subtitle="Alerting, allowlist, and integration credentials">
      <div className="grid gap-3 p-3 lg:grid-cols-2">
        <SectionCard title="Alert channels">
          <div className="space-y-3 p-4">
            <label className="block">
              <span className="label-caps">Slack incoming webhook</span>
              <input
                value={slack}
                onChange={(e) => setSlack(e.target.value)}
                placeholder="https://hooks.slack.com/services/…"
                className="mono-ip mt-1.5 h-8 w-full border border-input bg-surface-raised px-2 focus:border-primary focus:outline-none"
              />
            </label>
            <label className="block">
              <span className="label-caps">Email recipient</span>
              <input
                value={emailTo}
                onChange={(e) => setEmailTo(e.target.value)}
                className="mono-ip mt-1.5 h-8 w-full border border-input bg-surface-raised px-2 focus:border-primary focus:outline-none"
              />
            </label>
            <button
              type="button"
              onClick={() => toast.success("Alert channels saved")}
              className="h-8 border border-border-strong px-3 font-mono text-[10px] tracking-[0.12em] uppercase hover:border-primary hover:text-primary"
            >
              save channels
            </button>
          </div>
        </SectionCard>

        <SectionCard title="Integration credentials">
          <div className="px-4 pb-2">
            <CredentialField label="AWS API key (security groups)" hint="write-only · never redisplayed" />
            <CredentialField label="pfSense API token" hint="write-only · never redisplayed" />
          </div>
        </SectionCard>

        <SectionCard title="IP allowlist" className="lg:col-span-2">
          <div className="p-4">
            <p className="text-xs text-muted-foreground">
              Allowlisted sources are never blocked automatically — use for your own scanners and
              office egress.
            </p>
            <div className="mt-3 flex gap-2">
              <input
                value={newIp}
                onChange={(e) => setNewIp(e.target.value)}
                placeholder="203.0.113.0/24"
                className="mono-ip h-8 w-56 border border-input bg-surface-raised px-2 focus:border-primary focus:outline-none"
              />
              <button
                type="button"
                disabled={!newIp}
                onClick={() => {
                  setAllowlist((l) => [...l, newIp]);
                  setNewIp("");
                }}
                className="inline-flex h-8 items-center gap-1.5 border border-border-strong px-3 font-mono text-[10px] tracking-[0.12em] uppercase hover:border-primary hover:text-primary disabled:opacity-40"
              >
                <Plus className="h-3 w-3" /> add
              </button>
            </div>
            <ul className="mt-3 divide-y divide-border/60">
              {allowlist.map((ip) => (
                <li key={ip} className="flex items-center justify-between py-2">
                  <span className="mono-ip">{ip}</span>
                  <button
                    type="button"
                    aria-label={`Remove ${ip}`}
                    onClick={() => setAllowlist((l) => l.filter((x) => x !== ip))}
                    className="text-muted-foreground hover:text-sev-critical"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </SectionCard>
      </div>
    </AppShell>
  );
}

import { createFileRoute, Link } from "@tanstack/react-router";
import { Activity, ArrowRight, Radar, ShieldCheck, Waypoints } from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Sentinel Deception Grid — Honeypot-as-a-Service for SMBs" },
      {
        name: "description",
        content:
          "Deploy a decoy network in minutes. Sentinel captures real attacker behaviour on honeypots and auto-blocks hostile IPs at your firewall.",
      },
      { property: "og:title", content: "Sentinel Deception Grid — Honeypot-as-a-Service" },
      {
        property: "og:description",
        content:
          "Isolated honeypot fleet, live attacker graph, and automated firewall response for small businesses.",
      },
    ],
  }),
  component: Landing,
});

const FEATURES = [
  {
    icon: Waypoints,
    title: "Isolated decoy fleet",
    body: "Cowrie, Dionaea, fake wp-admin, RDP and SMB decoys in a VPC with no route to production.",
  },
  {
    icon: Radar,
    title: "Live attacker graph",
    body: "Every source IP becomes a node the moment it touches a decoy — sized by volume, coloured by severity.",
  },
  {
    icon: ShieldCheck,
    title: "Automated response",
    body: "Threshold rules push deny rules to AWS security groups or pfSense within seconds of a match.",
  },
];

function Landing() {
  return (
    <div className="min-h-screen bg-background">
      <header className="flex items-center justify-between border-b border-border px-6 py-4">
        <div className="flex items-center gap-2.5">
          <Activity className="h-4 w-4 text-primary" strokeWidth={2.5} />
          <span className="font-mono text-[13px] font-semibold tracking-[0.18em]">SENTINEL</span>
          <span className="label-caps hidden sm:inline">Deception Grid</span>
        </div>
        <nav className="flex items-center gap-2">
          <Link to="/login" className="label-caps px-3 py-2 hover:text-foreground">
            Sign in
          </Link>
          <Link
            to="/dashboard"
            className="flex items-center gap-1.5 border border-primary/40 bg-primary/10 px-3 py-2 font-mono text-[11px] tracking-[0.14em] text-primary uppercase transition-colors hover:bg-primary/20"
          >
            Open console <ArrowRight className="h-3 w-3" />
          </Link>
        </nav>
      </header>

      <section className="grid-field relative border-b border-border px-4 py-12 sm:px-6 sm:py-20">
        <div className="mx-auto max-w-4xl">
          <span className="label-caps border border-border bg-surface px-2 py-1.5">
            Honeypot-as-a-Service · SMB
          </span>
          <h1 className="mt-6 max-w-3xl text-4xl leading-[1.08] font-semibold tracking-tight text-balance md:text-6xl">
            Let attackers spend their time on
            <span className="text-primary"> machines that don&apos;t exist</span>.
          </h1>
          <p className="mt-5 max-w-xl text-sm leading-relaxed text-muted-foreground">
            Sentinel deploys an isolated network of convincing decoys in front of your business,
            records exactly what intruders type, and blocks them at the firewall before they find
            anything real.
          </p>
          <div className="mt-8 flex flex-wrap gap-2">
            <Link
              to="/dashboard"
              className="flex items-center gap-2 bg-primary px-4 py-2.5 font-mono text-[11px] tracking-[0.14em] text-primary-foreground uppercase hover:opacity-90"
            >
              Launch live console <ArrowRight className="h-3.5 w-3.5" />
            </Link>
            <Link
              to="/login"
              className="border border-border-strong px-4 py-2.5 font-mono text-[11px] tracking-[0.14em] uppercase hover:bg-surface"
            >
              Operator sign in
            </Link>
          </div>

          <dl className="mt-14 grid grid-cols-2 gap-px border border-border bg-border md:grid-cols-4">
            {[
              ["Decoy services", "5"],
              ["Median block time", "1.8s"],
              ["Events / day captured", "40k+"],
              ["Prod network exposure", "0"],
            ].map(([label, value]) => (
              <div key={label} className="bg-surface px-4 py-4">
                <dt className="label-caps">{label}</dt>
                <dd className="mt-2 font-mono text-xl tracking-tight">{value}</dd>
              </div>
            ))}
          </dl>
        </div>
      </section>

      <section className="px-6 py-16">
        <div className="mx-auto grid max-w-4xl gap-px bg-border md:grid-cols-3">
          {FEATURES.map(({ icon: Icon, title, body }) => (
            <article key={title} className="bg-surface p-5">
              <Icon className="h-4 w-4 text-primary" strokeWidth={1.75} />
              <h2 className="mt-3 text-sm font-semibold tracking-tight">{title}</h2>
              <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{body}</p>
            </article>
          ))}
        </div>
      </section>

      <footer className="border-t border-border px-6 py-6">
        <p className="label-caps">Sentinel Deception Grid — demo environment, seeded telemetry</p>
      </footer>
    </div>
  );
}

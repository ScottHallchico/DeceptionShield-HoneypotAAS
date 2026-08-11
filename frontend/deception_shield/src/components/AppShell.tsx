import { Link } from "@tanstack/react-router";
import { useEffect, useState, type ReactNode } from "react";
import {
  Activity,
  Crosshair,
  Menu,
  Radar,
  ScrollText,
  ServerCog,
  ShieldBan,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { useLiveContext } from "@/context/LiveEventsProvider";
import { useAuthStore } from "@/store/auth";
import { cn } from "@/lib/utils";
import { ThreatAssistant } from "@/components/ThreatAssistant";

const NAV = [
  { to: "/dashboard", label: "Threat Console", icon: Radar },
  { to: "/attackers", label: "Attackers", icon: Crosshair },
  { to: "/blocklist", label: "Blocklist & Response", icon: ShieldBan },
  { to: "/threat-ledger", label: "Threat Ledger", icon: ShieldCheck },
  { to: "/honeypots", label: "Fleet", icon: ServerCog },
  { to: "/settings", label: "Settings", icon: SlidersHorizontal },
] as const;


export function ConnectionPill() {
  const { connection, transport } = useLiveContext();
  const tone =
    connection === "live"
      ? "text-sev-low"
      : connection === "offline"
        ? "text-sev-critical"
        : "text-sev-medium";
  return (
    <div className="flex items-center gap-2 border border-border bg-surface-raised px-2.5 py-1">
      <span className={cn("relative flex h-1.5 w-1.5", tone)}>
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-current opacity-70" />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-current" />
      </span>
      <span className="label-caps !text-foreground">{connection}</span>
      <span className="label-caps">{transport === "seeded" ? "seed" : "ws"}</span>
    </div>
  );
}

function SidebarBody({ user, onNavigate }: { user: string | null; onNavigate?: () => void }) {
  return (
    <>
      <Link
        to="/"
        onClick={onNavigate}
        className="flex items-center gap-2.5 border-b border-border px-5 py-4"
      >
        <Activity className="h-4 w-4 shrink-0 text-primary" strokeWidth={2.5} />
        <div className="min-w-0 leading-none">
          <div className="font-mono text-[13px] font-semibold tracking-[0.18em] text-foreground">
            SENTINEL
          </div>
          <div className="label-caps mt-1">Deception Grid</div>
        </div>
      </Link>

      <nav className="flex flex-1 flex-col gap-0.5 p-2">
        {NAV.map(({ to, label, icon: Icon }) => (
          <Link
            key={to}
            to={to}
            onClick={onNavigate}
            className="group flex items-center gap-3 px-3 py-2.5 text-[13px] text-muted-foreground transition-colors hover:bg-surface-raised hover:text-foreground data-[status=active]:bg-surface-raised data-[status=active]:text-foreground"
            activeProps={{ className: "border-l-2 border-primary !pl-[10px]" }}
          >
            <Icon className="h-[15px] w-[15px] shrink-0" strokeWidth={1.75} />
            {label}
          </Link>
        ))}
      </nav>

      <div className="border-t border-border p-4">
        <div className="label-caps">Operator</div>
        <div className="mono-ip mt-1 truncate text-foreground">{user ?? "demo@sentinel.io"}</div>
      </div>
    </>
  );
}

export function AppShell({
  children,
  title,
  subtitle,
  actions,
}: {
  children: ReactNode;
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  const user = useAuthStore((s) => s.user);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenuOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menuOpen]);

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="sticky top-0 hidden h-screen w-[236px] shrink-0 flex-col border-r border-border bg-surface md:flex">
        <SidebarBody user={user} />
      </aside>

      {menuOpen ? (
        <div className="fixed inset-0 z-50 md:hidden">
          <button
            type="button"
            aria-label="Close navigation"
            onClick={() => setMenuOpen(false)}
            className="absolute inset-0 bg-background/80 backdrop-blur-sm"
          />
          <div className="relative flex h-full w-[264px] max-w-[82vw] flex-col border-r border-border bg-surface">
            <button
              type="button"
              aria-label="Close navigation"
              onClick={() => setMenuOpen(false)}
              className="absolute top-4 right-3 text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
            <SidebarBody user={user} onNavigate={() => setMenuOpen(false)} />
          </div>
        </div>
      ) : null}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 grid grid-cols-[auto_minmax(0,1fr)] items-center gap-3 border-b border-border bg-background/85 px-3 py-3 backdrop-blur sm:px-5 sm:py-3.5 md:grid-cols-[minmax(0,1fr)_auto]">
          <button
            type="button"
            aria-label="Open navigation"
            onClick={() => setMenuOpen(true)}
            className="flex h-8 w-8 shrink-0 items-center justify-center border border-border bg-surface-raised text-muted-foreground hover:text-foreground md:hidden"
          >
            <Menu className="h-4 w-4" />
          </button>
          <div className="min-w-0">
            <h1 className="truncate text-[15px] font-semibold tracking-tight text-foreground">
              {title}
            </h1>
            {subtitle ? (
              <p className="mt-0.5 truncate text-xs text-muted-foreground">{subtitle}</p>
            ) : null}
          </div>
          <div className="col-span-2 flex min-w-0 flex-wrap items-center gap-2 md:col-span-1 md:shrink-0 md:flex-nowrap md:justify-end">
            {actions}
            <ConnectionPill />
          </div>
        </header>
        <main className="min-w-0 flex-1">{children}</main>
      </div>

      <ThreatAssistant />
    </div>
  );
}


export function SectionCard({
  title,
  aside,
  children,
  className,
  bodyClassName,
}: {
  title: string;
  aside?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn("panel flex min-h-0 flex-col", className)}>
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2.5 sm:px-4 sm:py-2.5">
        <h2 className="label-caps !text-foreground">{title}</h2>
        {aside}
      </header>

      <div className={cn("min-h-0 flex-1", bodyClassName)}>{children}</div>
    </section>
  );
}

export function IconBadge({ children }: { children: ReactNode }) {
  return (
    <span className="label-caps border border-border bg-surface-raised px-1.5 py-1">{children}</span>
  );
}

export { ScrollText };

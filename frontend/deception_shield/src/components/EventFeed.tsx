import { useMemo } from "react";
import { List, type RowComponentProps } from "react-window";
import { Pause, Play, X } from "lucide-react";
import { useLiveEvents } from "@/hooks/useLiveEvents";
import { useUiStore } from "@/store/ui";
import { SEVERITY_BG, SEVERITY_TOKEN, filterEvents, formatTime } from "@/lib/severity";
import { HONEYPOTS } from "@/mock/seedEvents";
import type { AttackEvent, Severity, Technique } from "@/types/api";
import { cn } from "@/lib/utils";

const TECHNIQUES: Technique[] = [
  "brute_force",
  "credential_reuse",
  "payload_drop",
  "cve_exploit_attempt",
];
const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

function Row({
  index,
  style,
  events,
  onSelect,
  selectedIp,
}: RowComponentProps<{
  events: AttackEvent[];
  onSelect: (ip: string) => void;
  selectedIp: string | null;
}>) {
  const event = events[index];
  if (!event) return null;
  return (
    <button
      type="button"
      style={style}
      onClick={() => onSelect(event.attacker_ip)}
      data-testid="feed-row"
      className={cn(
        "flex w-full flex-col justify-center gap-1 border-b border-border/70 px-3 text-left transition-colors hover:bg-surface-raised",
        selectedIp === event.attacker_ip && "bg-surface-raised",
      )}
    >
      <div className="flex items-center gap-2">
        <span
          className="h-3.5 w-[3px] shrink-0"
          style={{ background: SEVERITY_TOKEN[event.severity] }}
        />
        <span className="mono-ip truncate text-foreground">{event.attacker_ip}</span>
        <span className="label-caps ml-auto shrink-0 tabular-nums">
          {formatTime(event.timestamp)}
        </span>
      </div>
      <div className="flex items-center gap-1.5 pl-[11px]">
        <span className={cn("label-caps px-1 py-0.5", SEVERITY_BG[event.severity])}>
          {event.severity}
        </span>
        <span className="label-caps truncate">{event.technique.replace(/_/g, " ")}</span>
        <span className="label-caps shrink-0">· {event.mitre_attck_id}</span>
      </div>
      <div className="truncate pl-[11px] font-mono text-[11px] text-muted-foreground">
        {event.honeypot_id} ← {event.geo.country}
      </div>
    </button>
  );
}

function FilterSelect<T extends string>({
  value,
  onChange,
  options,
  label,
}: {
  value: T | "all";
  onChange: (v: T | "all") => void;
  options: readonly T[];
  label: string;
}) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-1">
      <span className="label-caps">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as T | "all")}
        className="h-7 w-full border border-input bg-surface-raised px-1.5 font-mono text-[11px] text-foreground outline-none focus:border-primary"
      >
        <option value="all">all</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

export function EventFeed() {
  const { filters, setFilter, resetFilters, paused, togglePaused, selectedAttackerIp, selectAttacker } =
    useUiStore();
  const { events } = useLiveEvents({ limit: 800, paused });
  const visible = useMemo(() => filterEvents(events, filters), [events, filters]);
  const filterActive =
    filters.honeypot !== "all" ||
    filters.technique !== "all" ||
    filters.severity !== "all" ||
    filters.query !== "";

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="space-y-2 border-b border-border p-3">
        <div className="flex gap-2">
          <input
            value={filters.query}
            onChange={(e) => setFilter("query", e.target.value)}
            placeholder="filter ip / payload / org"
            className="mono-ip h-7 min-w-0 flex-1 border border-input bg-surface-raised px-2 text-foreground placeholder:text-muted-foreground/70 focus:border-primary focus:outline-none"
          />
          <button
            type="button"
            onClick={togglePaused}
            title={paused ? "Resume stream" : "Pause stream"}
            className={cn(
              "flex h-7 w-7 items-center justify-center border border-input bg-surface-raised text-muted-foreground hover:text-foreground",
              paused && "border-sev-medium text-sev-medium",
            )}
          >
            {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
          </button>
        </div>
        <div className="flex gap-2">
          <FilterSelect
            label="honeypot"
            value={filters.honeypot}
            onChange={(v) => setFilter("honeypot", v)}
            options={HONEYPOTS.map((h) => h.id)}
          />
          <FilterSelect
            label="technique"
            value={filters.technique}
            onChange={(v) => setFilter("technique", v)}
            options={TECHNIQUES}
          />
          <FilterSelect
            label="severity"
            value={filters.severity}
            onChange={(v) => setFilter("severity", v)}
            options={SEVERITIES}
          />
        </div>
        <div className="flex items-center justify-between">
          <span className="label-caps">
            {visible.length} of {events.length} events
          </span>
          {filterActive ? (
            <button
              type="button"
              onClick={resetFilters}
              className="label-caps flex items-center gap-1 hover:text-foreground"
            >
              <X className="h-3 w-3" /> clear
            </button>
          ) : null}
        </div>
      </div>

      <div className="min-h-0 flex-1">
        {visible.length === 0 ? (
          <p className="p-4 text-xs text-muted-foreground">
            No events match the current filters.
          </p>
        ) : (
          <List
            rowComponent={Row}
            rowCount={visible.length}
            rowHeight={62}
            rowProps={{ events: visible, onSelect: selectAttacker, selectedIp: selectedAttackerIp }}
            style={{ height: "100%", width: "100%" }}
          />
        )}
      </div>
    </div>
  );
}

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Pause, Play, RotateCcw } from "lucide-react";
import type { TerminalFrame } from "@/types/api";

const SPEEDS = [0.5, 1, 2, 4] as const;

/**
 * Scrubbable xterm.js playback of a captured Cowrie TTY session.
 * xterm is browser-only, so it is imported lazily after mount.
 */
export function SessionPlayer({ frames }: { frames: TerminalFrame[] }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<{ write: (d: string) => void; reset: () => void } | null>(null);
  const [ready, setReady] = useState(false);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState<number>(1);
  const [cursor, setCursor] = useState(0);
  const duration = useMemo(
    () => (frames.length ? frames[frames.length - 1]!.offset_ms + 1200 : 0),
    [frames],
  );

  useEffect(() => {
    let disposed = false;
    let term: import("@xterm/xterm").Terminal | null = null;
    let fit: import("@xterm/addon-fit").FitAddon | null = null;

    (async () => {
      const [{ Terminal }, { FitAddon }] = await Promise.all([
        import("@xterm/xterm"),
        import("@xterm/addon-fit"),
        import("@xterm/xterm/css/xterm.css"),
      ]);
      if (disposed || !hostRef.current) return;
      term = new Terminal({
        convertEol: true,
        cursorBlink: true,
        fontFamily: "JetBrains Mono, monospace",
        fontSize: 12.5,
        theme: {
          background: "#12161c",
          foreground: "#d6dbe3",
          cursor: "#7fe6d8",
          selectionBackground: "#2b6f70",
        },
      });
      fit = new FitAddon();
      term.loadAddon(fit);
      term.open(hostRef.current);
      fit.fit();
      termRef.current = term;
      setReady(true);
      const onResize = () => fit?.fit();
      window.addEventListener("resize", onResize);
      return () => window.removeEventListener("resize", onResize);
    })();

    return () => {
      disposed = true;
      term?.dispose();
      termRef.current = null;
    };
  }, []);

  // Re-render terminal content for the current cursor position.
  const renderTo = useCallback(
    (ms: number) => {
      const term = termRef.current;
      if (!term) return;
      term.reset();
      for (const f of frames) {
        if (f.offset_ms <= ms) term.write(f.data);
      }
    },
    [frames],
  );

  useEffect(() => {
    if (!ready) return;
    renderTo(cursor);
  }, [ready, cursor, renderTo]);

  useEffect(() => {
    if (!playing || !ready || duration === 0) return;
    const id = setInterval(() => {
      setCursor((c) => {
        const next = c + 120 * speed;
        if (next >= duration) {
          setPlaying(false);
          return duration;
        }
        return next;
      });
    }, 120);
    return () => clearInterval(id);
  }, [playing, ready, speed, duration]);

  if (!frames.length) {
    return (
      <div className="p-6 text-xs text-muted-foreground">
        No TTY capture for this session — only Cowrie SSH/Telnet sessions record a replayable shell.
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="scanline min-h-0 flex-1 overflow-hidden bg-[#12161c] p-3">
        <div ref={hostRef} className="h-full w-full" />
      </div>
      <div className="flex items-center gap-3 border-t border-border bg-surface px-3 py-2.5">
        <button
          type="button"
          onClick={() => {
            if (cursor >= duration) setCursor(0);
            setPlaying((p) => !p);
          }}
          aria-label={playing ? "Pause replay" : "Play replay"}
          className="flex h-7 w-7 items-center justify-center border border-border bg-surface-raised text-primary hover:border-primary"
        >
          {playing ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
        </button>
        <button
          type="button"
          onClick={() => {
            setCursor(0);
            setPlaying(true);
          }}
          aria-label="Restart replay"
          className="flex h-7 w-7 items-center justify-center border border-border bg-surface-raised text-muted-foreground hover:text-foreground"
        >
          <RotateCcw className="h-3.5 w-3.5" />
        </button>
        <input
          type="range"
          min={0}
          max={duration}
          value={cursor}
          aria-label="Seek session"
          onChange={(e) => {
            setPlaying(false);
            setCursor(Number(e.target.value));
          }}
          className="h-1 flex-1 cursor-pointer appearance-none rounded bg-border accent-[var(--primary)]"
        />
        <span className="label-caps tabular-nums">
          {(cursor / 1000).toFixed(1)}s / {(duration / 1000).toFixed(1)}s
        </span>
        <div className="flex border border-border">
          {SPEEDS.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSpeed(s)}
              className={
                "label-caps px-1.5 py-1 " +
                (speed === s ? "bg-primary/15 !text-primary" : "hover:text-foreground")
              }
            >
              {s}x
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

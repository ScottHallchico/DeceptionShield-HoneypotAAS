import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { isHeartbeat, type AttackEvent, type Heartbeat, type LiveMessage } from "@/types/api";
import { USE_MOCK, recordMockEvent, api } from "@/api/client";
import { SEED_EVENTS, startSeedStream, buildStats } from "@/mock/seedEvents";

export type ConnectionState = "connecting" | "live" | "reconnecting" | "offline";

type EventListener = (event: AttackEvent) => void;
type HeartbeatListener = (hb: Heartbeat) => void;

interface LiveContextValue {
  connection: ConnectionState;
  transport: "websocket" | "seeded";
  subscribeEvents: (fn: EventListener) => () => void;
  subscribeHeartbeat: (fn: HeartbeatListener) => () => void;
  /** Snapshot of recent events, newest first. Not reactive per-message. */
  buffer: () => AttackEvent[];
}

const LiveContext = createContext<LiveContextValue | null>(null);

const WS_URL =
  import.meta.env["VITE_WS_URL"] ??
  (typeof window !== "undefined"
    ? `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/ws/live`
    : "");

const MAX_BUFFER = 3000;

export function LiveEventsProvider({ children }: { children: ReactNode }) {
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const eventListeners = useRef(new Set<EventListener>());
  const heartbeatListeners = useRef(new Set<HeartbeatListener>());
  const bufferRef = useRef<AttackEvent[]>(USE_MOCK ? SEED_EVENTS.slice(0, MAX_BUFFER) : []);

  const emit = useCallback((msg: LiveMessage) => {
    if (isHeartbeat(msg)) {
      heartbeatListeners.current.forEach((fn) => fn(msg));
      return;
    }
    const event = msg.data;
    bufferRef.current = [event, ...bufferRef.current].slice(0, MAX_BUFFER);
    eventListeners.current.forEach((fn) => fn(event));
  }, []);

  useEffect(() => {
    if (USE_MOCK) {
      setConnection("live");
      const stopStream = startSeedStream((event) => {
        recordMockEvent(event);
        emit({ type: "event", data: event });
      });
      const hb = setInterval(() => {
        const buf = bufferRef.current;
        const dayAgo = Date.now() - 86_400_000;
        const stats = buildStats(buf);
        emit({
          type: "stats_heartbeat",
          data: {
            active_honeypots: stats.active_honeypots,
            total_events_24h: stats.total_events,
            active_blocks: stats.blocked_ips,
          },
        });
      }, 5000);
      return () => {
        stopStream();
        clearInterval(hb);
      };
    }

    // Real WebSocket transport with exponential-backoff reconnect.
    let socket: WebSocket | null = null;
    let attempt = 0;
    let retryTimer: ReturnType<typeof setTimeout>;
    let closed = false;

    const connect = () => {
      setConnection(attempt === 0 ? "connecting" : "reconnecting");
      try {
        socket = new WebSocket(WS_URL);
      } catch (err) {
        // SecurityError when mixing ws:// from https:// pages
        console.warn("[LiveEvents] WebSocket connect failed, falling back to REST poll:", err);
        setConnection("offline");
        
        // REST fallback: Populate initial buffer
        api.events().then((res) => {
          bufferRef.current = res.items;
          res.items.reverse().forEach((ev) => eventListeners.current.forEach((fn) => fn(ev)));
        });

        // REST fallback: Poll for stats and new events every 5 seconds
        const fallbackHb = setInterval(() => {
          api.stats().then((stats) => {
            emit({
              type: "stats_heartbeat",
              data: {
                active_honeypots: stats.active_honeypots,
                total_events_24h: stats.events_last_24h,
                active_blocks: stats.blocked_ips,
              },
            });
          });
          api.events().then((res) => {
            // Find new events that aren't in our buffer
            const newEvents = res.items.filter(
              (ev) => !bufferRef.current.some((b) => b.id === ev.id)
            );
            newEvents.reverse().forEach((ev) => emit({ type: "event", data: ev }));
          });
        }, 5000);
        
        retryTimer = fallbackHb;
        return;
      }
      socket.onopen = () => {
        attempt = 0;
        setConnection("live");
        // Pre-populate buffer with existing events from REST API
        api.events({ page_size: 200 }).then((res) => {
          if (res.items.length > 0) {
            bufferRef.current = res.items;
            // Notify listeners so the UI renders existing events
            res.items.slice().reverse().forEach((ev) => eventListeners.current.forEach((fn) => fn(ev)));
          }
        }).catch(() => { /* auth not ready yet — events will arrive via WS */ });
      };
      socket.onmessage = (msg) => {
        try {
          const parsed = JSON.parse(msg.data as string) as { type: string; data: unknown };
          if (parsed.type === "stats_heartbeat") {
            emit({ type: "stats_heartbeat", data: parsed.data } as Heartbeat);
          } else if (parsed.type === "event") {
            emit({ type: "event", data: parsed.data as AttackEvent });
          }
        } catch {
          /* ignore malformed frame */
        }
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        if (closed) return;
        attempt += 1;
        const backoff = Math.min(30_000, 500 * 2 ** attempt) + Math.random() * 400;
        setConnection(attempt > 6 ? "offline" : "reconnecting");
        retryTimer = setTimeout(connect, backoff);
      };
    };
    connect();

    return () => {
      closed = true;
      clearTimeout(retryTimer);
      socket?.close();
    };
  }, [emit]);

  const value = useMemo<LiveContextValue>(
    () => ({
      connection,
      transport: USE_MOCK ? "seeded" : "websocket",
      subscribeEvents: (fn) => {
        eventListeners.current.add(fn);
        return () => eventListeners.current.delete(fn);
      },
      subscribeHeartbeat: (fn) => {
        heartbeatListeners.current.add(fn);
        return () => heartbeatListeners.current.delete(fn);
      },
      buffer: () => bufferRef.current,
    }),
    [connection],
  );

  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLiveContext() {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error("useLiveContext must be used inside <LiveEventsProvider>");
  return ctx;
}

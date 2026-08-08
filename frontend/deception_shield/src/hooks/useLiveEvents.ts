import { useEffect, useRef, useState } from "react";
import { useLiveContext } from "@/context/LiveEventsProvider";
import type { AttackEvent, Heartbeat } from "@/types/api";

/**
 * Pub/sub subscription to the live stream. Each consumer opts into exactly the
 * slice it needs so a burst of events doesn't re-render the whole console.
 */
export function useLiveEvents(options: { limit?: number; paused?: boolean } = {}) {
  const { limit = 300, paused = false } = options;
  const { subscribeEvents, buffer, connection, transport } = useLiveContext();
  // Starts empty so SSR and the first client render agree; the buffered
  // snapshot is adopted right after hydration.
  const [events, setEvents] = useState<AttackEvent[]>([]);
  useEffect(() => {
    setEvents(buffer().slice(0, limit));
  }, [buffer, limit]);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    let queue: AttackEvent[] = [];
    let frame: number | null = null;

    const flush = () => {
      frame = null;
      if (!queue.length) return;
      const batch = queue;
      queue = [];
      setEvents((prev) => [...batch.reverse(), ...prev].slice(0, limit));
    };

    return subscribeEvents((event) => {
      if (pausedRef.current) return;
      queue.push(event);
      // Coalesce bursts into one render per animation frame.
      if (frame === null) frame = window.setTimeout(flush, 120);
    });
  }, [subscribeEvents, limit]);

  return { events, connection, transport };
}

/** Subscribe only to the 5s heartbeat (stats strip). */
export function useHeartbeat() {
  const { subscribeHeartbeat } = useLiveContext();
  const [hb, setHb] = useState<Heartbeat["data"] | null>(null);
  useEffect(() => subscribeHeartbeat((m) => setHb(m.data)), [subscribeHeartbeat]);
  return hb;
}

/** Fires the callback for each new event without triggering a re-render. */
export function useLiveEventListener(fn: (event: AttackEvent) => void) {
  const { subscribeEvents } = useLiveContext();
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => subscribeEvents((e) => ref.current(e)), [subscribeEvents]);
}

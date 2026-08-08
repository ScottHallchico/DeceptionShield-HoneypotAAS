import type {
  AssistantQueryResponse,
  AttackEvent,
  AttackerProfile,
  AuthTokens,
  BlocklistEntry,
  EventQuery,
  Honeypot,
  Paginated,
  ResponseRule,
  SessionDetail,
  Stats,
} from "@/types/api";
import { getAccessToken, useAuthStore } from "@/store/auth";
import {
  HONEYPOTS,
  MOCK_RULES,
  SEED_EVENTS,
  buildAttackers,
  buildBlocklist,
  buildSession,
  buildStats,
} from "@/mock/seedEvents";
import { parseIntent, retrieveEvents, synthesizeAnswer } from "@/lib/assistantRetrieval";

export const USE_MOCK =
  (import.meta.env["VITE_USE_MOCK_BACKEND"] ?? "true") !== "false";

const API_BASE = import.meta.env["VITE_API_BASE_URL"] ?? "/api";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getAccessToken();
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(init.headers ?? {}),
    },
  });
  if (res.status === 401 && path !== "/auth/refresh") {
    // Attempt to refresh the token
    try {
      const refreshRes = await fetch(`${API_BASE}/auth/refresh`, {
        method: "POST",
        credentials: "include",
      });
      if (refreshRes.ok) {
        const data = await refreshRes.json();
        // Update the access token in the store (assuming we can get the user name from somewhere or keep the existing one)
        const currentUser = useAuthStore.getState().user;
        useAuthStore.getState().setSession(data.access_token, currentUser ?? "admin");
        
        // Retry the original request with the new token
        const retryRes = await fetch(`${API_BASE}${path}`, {
          ...init,
          credentials: "include",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${data.access_token}`,
            ...(init.headers ?? {}),
          },
        });
        if (!retryRes.ok) throw new ApiError(`${init.method ?? "GET"} ${path} failed after refresh`, retryRes.status);
        return (await retryRes.json()) as T;
      } else {
        useAuthStore.getState().clear();
      }
    } catch {
      useAuthStore.getState().clear();
    }
  }

  if (!res.ok) throw new ApiError(`${init.method ?? "GET"} ${path} failed`, res.status);
  return (await res.json()) as T;
}

function qs(params: Record<string, string | number | undefined>) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") sp.set(k, String(v));
  const s = sp.toString();
  return s ? `?${s}` : "";
}

/* ---------- mock state (mutable, so unblock / redeploy feel real) ---------- */

const mockState = {
  honeypots: [...HONEYPOTS],
  rules: [...MOCK_RULES],
  blocklist: buildBlocklist(buildAttackers(SEED_EVENTS)),
  extraEvents: [] as AttackEvent[],
};

export function recordMockEvent(event: AttackEvent) {
  mockState.extraEvents = [event, ...mockState.extraEvents].slice(0, 4000);
}

function allMockEvents() {
  return [...mockState.extraEvents, ...SEED_EVENTS];
}

const delay = (ms = 180) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------- API surface ------------------------------ */

export const api = {
  async login(email: string, password: string): Promise<AuthTokens> {
    if (USE_MOCK) {
      await delay(420);
      if (!email || password.length < 4) throw new ApiError("Invalid credentials", 401);
      return { access_token: `demo.${btoa(email)}.jwt`, refresh_token: "cookie-managed" };
    }
    return request<AuthTokens>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  },

  async events(query: EventQuery = {}): Promise<Paginated<AttackEvent>> {
    if (USE_MOCK) {
      await delay();
      const page = query.page ?? 1;
      const filtered = allMockEvents().filter(
        (e) =>
          (!query.honeypot || e.honeypot_id === query.honeypot) &&
          (!query.severity || e.severity === query.severity) &&
          (!query.technique || e.technique === query.technique),
      );
      const size = 100;
      return {
        items: filtered.slice((page - 1) * size, page * size),
        page,
        page_size: size,
        total: filtered.length,
      };
    }
    return request<Paginated<AttackEvent>>(`/events${qs({ ...query })}`);
  },

  async session(sessionId: string): Promise<SessionDetail> {
    if (USE_MOCK) {
      await delay();
      return buildSession(sessionId, allMockEvents());
    }
    return request<SessionDetail>(`/events/${encodeURIComponent(sessionId)}`);
  },

  async attackers(sort = "threat_score"): Promise<Paginated<AttackerProfile>> {
    if (USE_MOCK) {
      await delay();
      const items = buildAttackers(allMockEvents());
      return { items, total: items.length, page: 1, page_size: items.length };
    }
    return request<Paginated<AttackerProfile>>(`/attackers${qs({ sort })}`);
  },

  async stats(): Promise<Stats> {
    if (USE_MOCK) {
      await delay();
      return buildStats(allMockEvents());
    }
    return request<Stats>("/stats");
  },

  async honeypots(): Promise<Honeypot[]> {
    if (USE_MOCK) {
      await delay();
      return mockState.honeypots;
    }
    return request<Honeypot[]>("/honeypots");
  },

  async redeployHoneypot(id: string): Promise<Honeypot> {
    if (USE_MOCK) {
      await delay(900);
      const idx = mockState.honeypots.findIndex((h) => h.id === id);
      const current = mockState.honeypots[idx];
      if (!current) throw new ApiError("Unknown honeypot", 404);
      const rotated: Honeypot = {
        ...current,
        ip_address: current.ip_address
          .split(".")
          .map((o, i) => (i === 3 ? String((Number(o) + 37) % 250 || 12) : o))
          .join("."),
        deployed_at: new Date().toISOString(),
        status: "running",
      };
      mockState.honeypots = mockState.honeypots.map((h) => (h.id === id ? rotated : h));
      return rotated;
    }
    return request<Honeypot>(`/honeypots/${encodeURIComponent(id)}/redeploy`, { method: "POST" });
  },

  async blocklist(): Promise<Paginated<BlocklistEntry>> {
    if (USE_MOCK) {
      await delay();
      return { items: mockState.blocklist, total: mockState.blocklist.length, page: 1, page_size: mockState.blocklist.length };
    }
    return request<Paginated<BlocklistEntry>>("/blocklist");
  },

  async unblock(ip: string): Promise<void> {
    if (USE_MOCK) {
      await delay(500);
      mockState.blocklist = mockState.blocklist.filter((b) => b.ip !== ip);
      return;
    }
    await request<void>(`/blocklist/${encodeURIComponent(ip)}/unblock`, { method: "POST" });
  },

  async rules(): Promise<ResponseRule[]> {
    if (USE_MOCK) {
      await delay();
      return mockState.rules;
    }
    return request<ResponseRule[]>("/rules");
  },

  async updateRule(rule: ResponseRule): Promise<ResponseRule> {
    if (USE_MOCK) {
      await delay(400);
      mockState.rules = mockState.rules.map((r) => (r.id === rule.id ? rule : r));
      return rule;
    }
    return request<ResponseRule>(`/rules/${encodeURIComponent(rule.id)}`, {
      method: "PUT",
      body: JSON.stringify(rule),
    });
  },

  /**
   * Natural-language query over live/historical telemetry. In mock mode this
   * runs real retrieval + aggregation against the in-memory event store (see
   * lib/assistantRetrieval.ts) and synthesizes an answer with templates. The
   * live backend instead embeds the question, does a pgvector similarity
   * search over event summaries plus a structured stats lookup, and asks an
   * LLM to answer grounded only on what was retrieved — same response shape
   * either way, so the UI never has to know which mode it's in.
   */
  async assistantQuery(question: string, conversationId?: string): Promise<AssistantQueryResponse> {
    if (USE_MOCK) {
      await delay(500);
      const honeypotIds = mockState.honeypots.map((h) => h.id);
      const intent = parseIntent(question, honeypotIds);
      const matched = retrieveEvents(allMockEvents(), intent);
      const { content, citations } = synthesizeAnswer(question, intent, matched);
      return {
        conversation_id: conversationId ?? crypto.randomUUID(),
        retrieved_event_count: matched.length,
        message: {
          id: crypto.randomUUID(),
          role: "assistant",
          content,
          citations,
          created_at: new Date().toISOString(),
        },
      };
    }
    return request<AssistantQueryResponse>("/assistant/query", {
      method: "POST",
      body: JSON.stringify({ question, conversation_id: conversationId }),
    });
  },
};

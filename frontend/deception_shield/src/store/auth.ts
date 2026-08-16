import { create } from "zustand";

/**
 * Session tokens are persisted in sessionStorage so the operator stays
 * logged in across page refreshes within the same tab. The token is
 * automatically cleared when the browser tab is closed.
 *
 * In production, the access token would be short-lived and the refresh
 * token would live in an httpOnly cookie set by the backend.
 */
interface AuthState {
  accessToken: string | null;
  user: string | null;
  setSession: (token: string, user: string) => void;
  clear: () => void;
}

function loadSession(): Pick<AuthState, "accessToken" | "user"> {
  if (typeof window === "undefined") return { accessToken: null, user: null };
  try {
    const accessToken = sessionStorage.getItem("ds_access_token");
    const user = sessionStorage.getItem("ds_user");
    return { accessToken, user };
  } catch {
    return { accessToken: null, user: null };
  }
}

export const useAuthStore = create<AuthState>((set) => ({
  ...loadSession(),
  setSession: (accessToken, user) => {
    try {
      sessionStorage.setItem("ds_access_token", accessToken);
      sessionStorage.setItem("ds_user", user);
    } catch {
      // sessionStorage unavailable — fall back to memory-only
    }
    set({ accessToken, user });
  },
  clear: () => {
    try {
      sessionStorage.removeItem("ds_access_token");
      sessionStorage.removeItem("ds_user");
    } catch {
      // ignore
    }
    set({ accessToken: null, user: null });
  },
}));

export function getAccessToken() {
  return useAuthStore.getState().accessToken;
}

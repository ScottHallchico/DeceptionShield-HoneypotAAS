import { create } from "zustand";

/**
 * Access token is held in memory only (never localStorage / sessionStorage) so a
 * successful XSS cannot lift a long-lived credential out of storage. The refresh
 * token lives in an httpOnly cookie set by the backend.
 */
interface AuthState {
  accessToken: string | null;
  user: string | null;
  setSession: (token: string, user: string) => void;
  clear: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  accessToken: null,
  user: null,
  setSession: (accessToken, user) => set({ accessToken, user }),
  clear: () => set({ accessToken: null, user: null }),
}));

export function getAccessToken() {
  return useAuthStore.getState().accessToken;
}

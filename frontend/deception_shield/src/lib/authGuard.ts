import { redirect } from "@tanstack/react-router";
import { useAuthStore } from "@/store/auth";

/**
 * beforeLoad guard for any route that requires an authenticated operator.
 * Redirects to /login (preserving the attempted destination) if no access
 * token is present in memory. Since the access token intentionally lives in
 * memory only (see store/auth.ts), a hard page refresh will also require
 * re-authentication — that is expected behaviour, not a bug.
 */
export function requireAuth({ location }: { location: { href: string } }) {
  const token = useAuthStore.getState().accessToken;
  if (!token) {
    throw redirect({
      to: "/login",
      search: { redirect: location.href },
    });
  }
}

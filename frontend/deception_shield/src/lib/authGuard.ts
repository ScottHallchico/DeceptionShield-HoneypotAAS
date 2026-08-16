import { redirect } from "@tanstack/react-router";
import { useAuthStore } from "@/store/auth";

/**
 * beforeLoad guard for any route that requires an authenticated operator.
 * Redirects to /login (preserving the attempted destination) if no access
 * token is present. Checks both the Zustand store and sessionStorage to
 * handle SSR hydration and page-refresh scenarios.
 */
export function requireAuth({ location }: { location: { href: string } }) {
  if (typeof window === "undefined") {
    // In SSR, we don't have access to sessionStorage where the token is stored.
    // If we redirect here, the server will send a 302 to /login before the
    // client ever gets a chance to hydrate and check its sessionStorage.
    // So we defer the auth check to the client.
    return;
  }

  // Check Zustand store first (client hot path)
  let token = useAuthStore.getState().accessToken;

  // On page refresh, Zustand may not have hydrated yet from sessionStorage.
  if (!token) {
    try {
      token = sessionStorage.getItem("ds_access_token");
      if (token) {
        // Re-hydrate the Zustand store so downstream components see the token
        const user = sessionStorage.getItem("ds_user") ?? "admin";
        useAuthStore.getState().setSession(token, user);
      }
    } catch {
      // sessionStorage unavailable
    }
  }

  if (!token) {
    throw redirect({
      to: "/login",
      search: { redirect: location.href },
    });
  }
}

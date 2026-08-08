import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { z } from "zod";
import { Activity, Loader2 } from "lucide-react";
import { api } from "@/api/client";
import { useAuthStore } from "@/store/auth";

const loginSearchSchema = z.object({
  redirect: z.string().optional(),
});

export const Route = createFileRoute("/login")({
  validateSearch: loginSearchSchema,
  head: () => ({
    meta: [
      { title: "Operator Sign In — Sentinel Deception Grid" },
      {
        name: "description",
        content: "Sign in to the Sentinel honeypot console to review live attacks and responses.",
      },
      { property: "og:title", content: "Operator Sign In — Sentinel" },
      { property: "og:description", content: "Access the Sentinel deception console." },
    ],
  }),
  component: LoginPage,
});

const DEMO_EMAIL = "admin@honeypot.io";
const DEMO_PASSWORD = "honeypot-admin-2024";

function LoginPage() {
  const navigate = useNavigate();
  const { redirect: redirectTo } = Route.useSearch();
  const setSession = useAuthStore((s) => s.setSession);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const tokens = await api.login(email || DEMO_EMAIL, password || DEMO_PASSWORD);
      // Access token kept in memory only; refresh token arrives as an httpOnly cookie.
      setSession(tokens.access_token, email || DEMO_EMAIL);
      navigate({ to: redirectTo || "/dashboard" });
    } catch {
      setError("Authentication failed — check the operator credentials.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid-field flex min-h-screen items-center justify-center px-4">
      <div className="panel w-full max-w-sm p-6">
        <div className="flex items-center gap-2.5">
          <Activity className="h-4 w-4 text-primary" strokeWidth={2.5} />
          <span className="font-mono text-[13px] font-semibold tracking-[0.18em]">SENTINEL</span>
        </div>
        <h1 className="mt-5 text-lg font-semibold tracking-tight">Operator sign in</h1>
        <p className="mt-1 text-xs text-muted-foreground">
          Tokens are held in memory only — nothing is written to browser storage.
        </p>

        <form onSubmit={submit} className="mt-6 space-y-3">
          <label className="block">
            <span className="label-caps">Email</span>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder={DEMO_EMAIL}
              autoComplete="username"
              className="mono-ip mt-1.5 h-9 w-full border border-input bg-surface-raised px-2.5 text-foreground placeholder:text-muted-foreground/60 focus:border-primary focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="label-caps">Password</span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={DEMO_PASSWORD}
              autoComplete="current-password"
              className="mono-ip mt-1.5 h-9 w-full border border-input bg-surface-raised px-2.5 text-foreground placeholder:text-muted-foreground/60 focus:border-primary focus:outline-none"
            />
          </label>

          {error ? <p className="text-xs text-sev-critical">{error}</p> : null}

          <button
            type="submit"
            disabled={busy}
            className="flex h-9 w-full items-center justify-center gap-2 bg-primary font-mono text-[11px] tracking-[0.14em] text-primary-foreground uppercase hover:opacity-90 disabled:opacity-60"
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            {busy ? "authenticating" : "sign in"}
          </button>
        </form>

        <p className="label-caps mt-4">
          Demo: leave both fields blank to sign in as {DEMO_EMAIL}
        </p>
      </div>
    </div>
  );
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import type { EventQuery, ResponseRule } from "@/types/api";
import { toast } from "sonner";

export const keys = {
  events: (q: EventQuery) => ["events", q] as const,
  session: (id: string) => ["session", id] as const,
  attackers: () => ["attackers"] as const,
  stats: () => ["stats"] as const,
  honeypots: () => ["honeypots"] as const,
  blocklist: () => ["blocklist"] as const,
  rules: () => ["rules"] as const,
};

export const useEvents = (q: EventQuery = {}) =>
  useQuery({ queryKey: keys.events(q), queryFn: () => api.events(q) });

export const useSession = (id: string) =>
  useQuery({ queryKey: keys.session(id), queryFn: () => api.session(id) });

export const useAttackers = () =>
  useQuery({ queryKey: keys.attackers(), queryFn: () => api.attackers(), staleTime: 15_000 });

export const useStats = () =>
  useQuery({ queryKey: keys.stats(), queryFn: () => api.stats(), staleTime: 30_000 });

export const useHoneypots = () =>
  useQuery({ queryKey: keys.honeypots(), queryFn: () => api.honeypots() });

export const useBlocklist = () =>
  useQuery({ queryKey: keys.blocklist(), queryFn: () => api.blocklist() });

export const useRules = () => useQuery({ queryKey: keys.rules(), queryFn: () => api.rules() });

export function useAssistantQuery() {
  return useMutation({
    mutationFn: ({ question, conversationId }: { question: string; conversationId?: string }) =>
      api.assistantQuery(question, conversationId),
  });
}

export function useRedeployHoneypot() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.redeployHoneypot(id),
    onSuccess: (hp) => {
      qc.invalidateQueries({ queryKey: keys.honeypots() });
      toast.success(`${hp.id} redeployed`, { description: `New public address ${hp.ip_address}` });
    },
    onError: () => toast.error("Redeploy failed"),
  });
}

export function useUnblockIp() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (ip: string) => api.unblock(ip),
    onSuccess: (_d, ip) => {
      qc.invalidateQueries({ queryKey: keys.blocklist() });
      toast.success(`${ip} unblocked`, { description: "Firewall rule withdrawn" });
    },
    onError: () => toast.error("Unblock failed"),
  });
}

export function useUpdateRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (rule: ResponseRule) => api.updateRule(rule),
    onSuccess: (rule) => {
      qc.invalidateQueries({ queryKey: keys.rules() });
      toast.success(`Rule "${rule.name}" saved`, { description: "Applied without redeploy" });
    },
    onError: () => toast.error("Could not save rule"),
  });
}

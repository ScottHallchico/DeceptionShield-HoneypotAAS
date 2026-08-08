import { create } from "zustand";
import type { Severity, Technique } from "@/types/api";

export interface FeedFilters {
  honeypot: string | "all";
  technique: Technique | "all";
  severity: Severity | "all";
  query: string;
}

interface UiState {
  filters: FeedFilters;
  setFilter: <K extends keyof FeedFilters>(key: K, value: FeedFilters[K]) => void;
  resetFilters: () => void;
  selectedAttackerIp: string | null;
  selectAttacker: (ip: string | null) => void;
  paused: boolean;
  togglePaused: () => void;
}

const DEFAULT_FILTERS: FeedFilters = {
  honeypot: "all",
  technique: "all",
  severity: "all",
  query: "",
};

export const useUiStore = create<UiState>((set) => ({
  filters: DEFAULT_FILTERS,
  setFilter: (key, value) => set((s) => ({ filters: { ...s.filters, [key]: value } })),
  resetFilters: () => set({ filters: DEFAULT_FILTERS }),
  selectedAttackerIp: null,
  selectAttacker: (ip) => set({ selectedAttackerIp: ip }),
  paused: false,
  togglePaused: () => set((s) => ({ paused: !s.paused })),
}));

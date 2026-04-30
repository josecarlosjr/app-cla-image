import axios from "axios";

const API_BASE = import.meta.env.VITE_API_BASE || "/agent-api";

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 60_000,
});

export type Job = {
  id: number;
  company: string;
  role: string;
  url: string;
  status: string;
  notes: string;
  created: string;
  updated: string;
};

export type Pattern = {
  id: number;
  analysis: string;
  confidence: "ALTA" | "MEDIA" | "BAIXA";
  categories: string[];
  sources: string[];
  num_sources: number;
  timestamp: string;
  articles: { title: string; source: string; url: string }[];
};

export type CryptoScan = {
  coin_id: string;
  name: string;
  symbol: string;
  price_usd: number;
  change_24h: number;
  date: string;
  timestamp: string;
  analysis: string;
};

export type Article = {
  title: string;
  summary: string;
  url: string;
  source: string;
  category: string;
  published: string;
  fetched_at: string;
  relevance_score?: number;
  relevance_trusted?: boolean;
};

export type MapNode = {
  id: string;
  score: number;
  trend: "rising" | "falling" | "stable";
  articles: number;
};

export type MapConnection = {
  from: string;
  to: string;
  score: number;
  pattern: string;
};

export type CryptoMover = {
  id: string;
  name: string;
  symbol: string;
  image: string;
  price_usd: number;
  change_1h: number;
  change_24h: number;
  change_7d: number;
  market_cap: number;
  market_cap_rank: number | null;
  volume_24h: number;
};

export type Prices = Record<
  string,
  { usd?: number; eur?: number; usd_24h_change?: number }
>;

export type MemoryStats = {
  total_messages: number;
  user_messages: number;
  assistant_messages: number;
  facts_count: number;
  facts: string[];
};

export type SupplyChainNode = {
  id: string;
  name: string;
  type: "mineral" | "component" | "product" | "infra";
  keywords: string[];
  mentions_7d: number;
  sentiments: Record<string, number>;
};

export type SupplyChainEdge = {
  src: string;
  dst: string;
  relation: string;
  weight: number;
};

export type SupplyChainGraph = {
  nodes: SupplyChainNode[];
  edges: SupplyChainEdge[];
};

export type SupplyChainSpike = {
  node_id: string;
  total_24h: number;
  daily_avg_7d: number;
  ratio: number;
  dominant_signal: "negative" | "positive" | "neutral";
  sentiments: Record<string, number>;
};

export type SupplyChainAlert = {
  type: "spike" | "propagation" | "correlated_chain";
  node_id: string;
  text: string;
};

export type SupplyChainAnalysis = {
  spikes: SupplyChainSpike[];
  propagated_risks: any[];
  correlated_chains: any[];
  alerts: SupplyChainAlert[];
};

export type SupplyChainImpact = {
  node_id: string;
  impact_chain: { from: string; to: string; depth: number }[];
  dependents: string[];
  dependencies: string[];
};

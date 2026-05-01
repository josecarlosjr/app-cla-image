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

export type BacktestTick = {
  at: string;
  articles_visible: number;
  articles_by_category: Record<string, number>;
  patterns_visible: number;
  patterns_by_confidence: Record<string, number>;
  chains_visible: number;
  chain_pillars: string[][];
};

export type BacktestResult = {
  window_start: string;
  window_end: string;
  ticks: BacktestTick[];
  summary: {
    tick_count: number;
    eval_step_hours: number;
    pattern_lookback_hours: number;
    total_articles_observed: number;
    total_patterns_observed: number;
    total_chains_observed: number;
  };
  quality?: QualityMetrics;
  outcomes_in_window?: Record<string, number>;
  run_id?: number;
};

export type BacktestRun = {
  id: number;
  window_start: string;
  window_end: string;
  config: Record<string, any>;
  result: BacktestResult;
  created_at: string;
};

export type SystemSnapshot = {
  id: number;
  snapshot_type: string;
  captured_at: string;
  data: any;
};

export type EventOutcome = {
  id: number;
  event_type: string;
  event_id: string;
  outcome: "true_positive" | "false_positive" | "unclear";
  notes: string;
  event_timestamp: string;
  marked_at: string;
};

export type QualityMetrics = {
  window_days: number;
  by_type: Record<string, {
    true_positive: number;
    false_positive: number;
    unclear: number;
    total: number;
    precision: number | null;
  }>;
};

export type GraphEntity = {
  id: number;
  name: string;
  canonical: string;
  entity_type: string;
  pillar: string;
  first_seen: string;
  source_url: string;
  mention_count: number;
  status: string;
  reviewed_at: string;
};

export type GraphRelationship = {
  id: number;
  subject_id: number;
  predicate: string;
  object_id: number;
  confidence: number;
  source_url: string;
  first_seen: string;
  mention_count: number;
  status: string;
  reviewed_at: string;
  subject_name: string;
  subject_canonical: string;
  object_name: string;
  object_canonical: string;
};

export type GraphStats = {
  entities: Record<string, number>;
  relationships: Record<string, number>;
};

export type CrossPillarEvent = {
  kind: "pattern" | "spike" | "correlated_chain" | "temporal";
  id: string;
  pillar: string;
  category: string;
  timestamp: string;
  label: string;
  confidence?: string;
  source_count?: number;
  ratio?: number;
  signal?: string;
  alert_type?: string;
};

export type CrossPillarChain = {
  id?: number;
  members_hash: string;
  window_start: string;
  window_end: string;
  pillars: string[];
  events: CrossPillarEvent[];
  events_by_pillar?: Record<string, CrossPillarEvent[]>;
  total_events?: number;
  narrative?: string;
  detected_at?: string;
};

export type CrossPillarActiveResponse = {
  chains: CrossPillarChain[];
  pillar_labels: Record<string, string>;
  window_hours: number;
};

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
  filter_by?: string;
  by_type: Record<string, {
    true_positive: number;
    false_positive: number;
    unclear: number;
    total: number;
    n?: number;
    precision: number | null;
    precision_low?: number | null;
    precision_high?: number | null;
  }>;
};

export type UnlabelledEvent = {
  event_type: string;
  event_id: string;
  kind: string;
  title: string;
  detail: string;
  timestamp: string;
};

export type UnlabelledResponse = {
  events: UnlabelledEvent[];
  total: number;
  limit: number;
  offset: number;
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

// ---------------------------------------------------------------------------
// Quant Dashboard (Onda 12)
// ---------------------------------------------------------------------------

export type QuantSeriesPoint = { ts: string; value: number };

export type QuantWatchlistRow = {
  ticker: string;
  ts: string;
  close: number;
  change_pct_1d: number | null;
  change_pct_30d: number | null;
  pe: number | null;
  market_cap: number | null;
  // Phase 4 detector output (null until quant_detectors cron has run
  // for this ticker).
  lppl_bubble_prob: number | null;
  gsadf_bsadf: number | null;
  gsadf_explosive: boolean;
};

// Macro-risk panel — Onda 12 integration Phase A. Each field maps to
// one of the three new ingesters (BIS credit-to-GDP gap, Eurostat HPI,
// BPstat) writing into quant_indicators. Empty until the corresponding
// weekly cron has run at least once.
//
// `series` (Phase B) carries the recent ~7 years of quarterly
// observations for the sparkline. Optional so an older backend that
// hasn't shipped Phase B still type-checks against the frontend.
export type QuantLatestPoint = {
  ts: string;
  value: number;
  series?: QuantSeriesPoint[];
};
export type QuantHpiPoint = QuantLatestPoint & {
  yoy_pct: number | null;
};

export type QuantMacroRisk = {
  credit_gap: Record<string, QuantLatestPoint>;
  hpi: Record<string, QuantHpiPoint>;
  bpstat: Record<string, QuantHpiPoint>;
};

// Per-country detail — Onda 13 multi-pais, Camada B. Served on demand
// by GET /api/macro/country/{code} when a country row in the macro-risk
// panel is opened; deliberately NOT part of QuantDashboard, so the full
// 1980-> history (~184 quarterly points per series) never rides along
// in the dashboard payload.
//
// `series` is required here (unlike QuantLatestPoint, where it was
// additive): this endpoint shipped with it from the start, and the
// charts have nothing to draw without it. A block is `null` when the
// country is valid but that series has no rows — the drawer says so
// rather than rendering an empty chart.
export type MacroCountryPoint = {
  ts: string;
  value: number;
  series: QuantSeriesPoint[];
};
export type MacroCountryHpi = MacroCountryPoint & {
  yoy_pct: number | null;
};
// `unit` is "%" for a series that IS a rate (BPstat 5739035, the
// year-on-year change) and "" for an index level. It comes from the
// backend rather than being inferred here so the axis, the tooltip and
// the headline can't disagree about what the number means.
//
// `yoy_pct` is null for a series that is already a year-on-year: a
// y-o-y of a y-o-y is the change OF a change, not a price move.
export type MacroCountryBpstat = MacroCountryHpi & {
  series_id: string;
  label: string;
  unit: string;
};

export type MacroCountryDetail = {
  country: string;
  credit_gap: MacroCountryPoint | null;
  credit_ratio: MacroCountryPoint | null;
  hpi: MacroCountryHpi | null;
  bpstat: MacroCountryBpstat[];
};

// The four risk dimensions (Onda 13 Sprint 4). Served by
// risk_dimensions.py, which keeps every threshold next to the text
// explaining where it came from — so the UI never has to invent a
// justification for a number it is rendering.
//
// `anchor_kind` is the honesty flag: "external" means someone else
// fixed the number (a null-distribution percentile, a Basel trigger,
// the asset's own history) and we adopted it; "design" means we chose
// it. `caveat` carries the admission for the bands that are design
// choices — the amber ones, mostly.
export type RiskDimension = {
  key: "explosive" | "valuation" | "credit" | "stress";
  label: string;
  state: "calm" | "watch" | "danger" | "unknown";
  value: number | null;
  display: string;
  measures: string;
  applied: string;
  anchor: string;
  anchor_kind: "external" | "design";
  caveat?: string | null;
  ticker?: string;
  run?: number;
  country?: string;
  drawdown_pct?: number | null;
  vix?: number | null;
};

export type RiskDimensionsPanel = {
  dimensions: RiskDimension[];
  legend: { key: string; label: string; short: string }[];
  scope: string;
};

export type QuantDashboard = {
  yield_curve: {
    T10Y3M: QuantSeriesPoint[];
    T10Y2Y: QuantSeriesPoint[];
    latest_t10y3m_bps: number | null;
    inverted: boolean;
  };
  credit: {
    HY: QuantSeriesPoint[];
    BBB: QuantSeriesPoint[];
    latest_hy_pct: number | null;
    hy_status: "tight" | "normal" | "elevated" | "stress" | "unknown";
  };
  vix: {
    series: QuantSeriesPoint[];
    latest: number | null;
    status: "calm" | "nervous" | "fear" | "panic" | "unknown";
  };
  macro_risk: QuantMacroRisk;
  risk_dimensions?: RiskDimensionsPanel;
  watchlist: QuantWatchlistRow[];
  updated_at: string;
};

export type QuantHealth = {
  quant_indicators: number;
  quant_bars: number;
  quant_valuations: number;
  quant_features: number;
};

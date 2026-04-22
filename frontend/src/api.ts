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

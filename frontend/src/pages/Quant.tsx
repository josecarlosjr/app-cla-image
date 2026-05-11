import { useEffect, useState, useCallback } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  Legend,
} from "recharts";
import { api, QuantDashboard, QuantSeriesPoint } from "../api";

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("pt-BR", { day: "2-digit", month: "short" });
}

function formatPct(v: number | null | undefined): string {
  if (v === null || v === undefined) return "—";
  return `${v > 0 ? "+" : ""}${v.toFixed(2)}%`;
}

function formatCap(v: number | null | undefined): string {
  if (v === null || v === undefined) return "—";
  if (v >= 1e12) return `${(v / 1e12).toFixed(2)}T`;
  if (v >= 1e9) return `${(v / 1e9).toFixed(2)}B`;
  if (v >= 1e6) return `${(v / 1e6).toFixed(0)}M`;
  return v.toFixed(0);
}

function formatBps(v: number | null | undefined): string {
  if (v === null || v === undefined) return "—";
  return `${v > 0 ? "+" : ""}${v.toFixed(0)} bps`;
}

// Merge multiple time series into a single array keyed by ts. Each
// row gets the series name as a column so recharts can plot multiple
// Lines from the same dataset.
function mergeSeries(
  series: { name: string; data: QuantSeriesPoint[] }[],
): Array<Record<string, number | string>> {
  const map = new Map<string, Record<string, number | string>>();
  for (const { name, data } of series) {
    for (const p of data) {
      const key = p.ts.substring(0, 10); // YYYY-MM-DD bucket
      if (!map.has(key)) map.set(key, { ts: key });
      map.get(key)![name] = p.value;
    }
  }
  return Array.from(map.values()).sort((a, b) =>
    (a.ts as string).localeCompare(b.ts as string),
  );
}

// ---------------------------------------------------------------------------
// Status styling (matches the qualitative labels server returns)
// ---------------------------------------------------------------------------

const STATUS_PILL: Record<string, string> = {
  normal: "bg-emerald-500/20 text-emerald-400",
  calm: "bg-emerald-500/20 text-emerald-400",
  tight: "bg-amber-500/20 text-amber-400",
  nervous: "bg-amber-500/20 text-amber-400",
  elevated: "bg-amber-500/20 text-amber-400",
  fear: "bg-red-500/20 text-red-400",
  stress: "bg-red-500/20 text-red-400",
  panic: "bg-red-500/20 text-red-400",
  unknown: "bg-slate-500/20 text-slate-400",
  inverted: "bg-red-500/20 text-red-400",
};

const STATUS_LABEL: Record<string, string> = {
  normal: "normal",
  calm: "calmo",
  tight: "tight (frothy)",
  nervous: "nervoso",
  elevated: "elevado",
  fear: "medo",
  stress: "stress",
  panic: "pânico",
  unknown: "—",
  inverted: "invertida",
};

// ---------------------------------------------------------------------------
// Chart components
// ---------------------------------------------------------------------------

const TOOLTIP_STYLE = {
  backgroundColor: "#0f172a",
  border: "1px solid #334155",
  borderRadius: "0.5rem",
  fontSize: "12px",
};

function YieldCurveChart({ yc }: { yc: QuantDashboard["yield_curve"] }) {
  const data = mergeSeries([
    { name: "T10Y3M", data: yc.T10Y3M },
    { name: "T10Y2Y", data: yc.T10Y2Y },
  ]);
  if (data.length === 0) return <EmptyChart />;
  return (
    <ResponsiveContainer width="100%" height={260}>
      <LineChart data={data} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis
          dataKey="ts"
          tickFormatter={formatDate}
          stroke="#94a3b8"
          fontSize={11}
        />
        <YAxis
          stroke="#94a3b8"
          fontSize={11}
          tickFormatter={(v) => `${Number(v).toFixed(1)}%`}
        />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          labelFormatter={formatDate}
          formatter={(v: any) => `${Number(v).toFixed(3)}%`}
        />
        <Legend wrapperStyle={{ fontSize: 11 }} />
        <ReferenceLine
          y={0}
          stroke="#ef4444"
          strokeDasharray="3 3"
          label={{ value: "inversão", fill: "#ef4444", fontSize: 10, position: "left" }}
        />
        <Line type="monotone" dataKey="T10Y3M" stroke="#3b82f6" dot={false} strokeWidth={2} />
        <Line type="monotone" dataKey="T10Y2Y" stroke="#10b981" dot={false} strokeWidth={2} />
      </LineChart>
    </ResponsiveContainer>
  );
}

function CreditChart({ credit }: { credit: QuantDashboard["credit"] }) {
  const data = mergeSeries([
    { name: "HY OAS", data: credit.HY },
    { name: "BBB OAS", data: credit.BBB },
  ]);
  if (data.length === 0) return <EmptyChart />;
  return (
    <ResponsiveContainer width="100%" height={260}>
      <LineChart data={data} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis
          dataKey="ts"
          tickFormatter={formatDate}
          stroke="#94a3b8"
          fontSize={11}
        />
        <YAxis
          stroke="#94a3b8"
          fontSize={11}
          tickFormatter={(v) => `${Number(v).toFixed(1)}%`}
        />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          labelFormatter={formatDate}
          formatter={(v: any) => `${Number(v).toFixed(2)}%`}
        />
        <Legend wrapperStyle={{ fontSize: 11 }} />
        <ReferenceLine y={3} stroke="#f59e0b" strokeDasharray="2 2" />
        <ReferenceLine y={5} stroke="#ef4444" strokeDasharray="2 2" />
        <Line type="monotone" dataKey="HY OAS" stroke="#ef4444" dot={false} strokeWidth={2} />
        <Line type="monotone" dataKey="BBB OAS" stroke="#3b82f6" dot={false} strokeWidth={2} />
      </LineChart>
    </ResponsiveContainer>
  );
}

function VixChart({ vix }: { vix: QuantDashboard["vix"] }) {
  const data = vix.series.map((p) => ({
    ts: p.ts.substring(0, 10),
    value: p.value,
  }));
  if (data.length === 0) return <EmptyChart />;
  return (
    <ResponsiveContainer width="100%" height={260}>
      <LineChart data={data} margin={{ top: 10, right: 70, bottom: 0, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis
          dataKey="ts"
          tickFormatter={formatDate}
          stroke="#94a3b8"
          fontSize={11}
        />
        <YAxis stroke="#94a3b8" fontSize={11} />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          labelFormatter={formatDate}
          formatter={(v: any) => Number(v).toFixed(2)}
        />
        <ReferenceLine
          y={15}
          stroke="#10b981"
          strokeDasharray="2 2"
          label={{ value: "calmo", fill: "#10b981", fontSize: 10, position: "right" }}
        />
        <ReferenceLine
          y={25}
          stroke="#f59e0b"
          strokeDasharray="2 2"
          label={{ value: "nervoso", fill: "#f59e0b", fontSize: 10, position: "right" }}
        />
        <ReferenceLine
          y={40}
          stroke="#ef4444"
          strokeDasharray="2 2"
          label={{ value: "medo", fill: "#ef4444", fontSize: 10, position: "right" }}
        />
        <Line type="monotone" dataKey="value" stroke="#8b5cf6" dot={false} strokeWidth={2} />
      </LineChart>
    </ResponsiveContainer>
  );
}

function EmptyChart() {
  return (
    <div className="h-[260px] flex items-center justify-center text-sm text-slate-500">
      Sem dados ainda — aguarde o primeiro run do cron de ingestão.
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function Quant() {
  const [data, setData] = useState<QuantDashboard | null>(null);
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const resp = await api.get<QuantDashboard>("/quant/dashboard");
      setData(resp.data);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || "erro desconhecido");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold">Quant Dashboard</h1>
          <p className="text-slate-400 mt-1">
            Indicadores macro e cross-asset — yield curve, credit spreads, volatilidade.
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="px-4 py-2 bg-primary-500 hover:bg-primary-600 disabled:opacity-50 rounded-lg text-sm font-medium transition"
        >
          {loading ? "Carregando..." : "Atualizar"}
        </button>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/40 rounded-lg p-4 text-sm text-red-400">
          Erro ao carregar dados: {error}
        </div>
      )}

      {!error && !data && !loading && (
        <div className="text-slate-500 text-sm">Sem dados ainda.</div>
      )}

      {data && (
        <>
          {/* Summary row */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <SummaryCard
              title="Yield curve (10Y - 3M)"
              value={formatBps(data.yield_curve.latest_t10y3m_bps)}
              statusKey={data.yield_curve.inverted ? "inverted" : "normal"}
            />
            <SummaryCard
              title="HY OAS"
              value={
                data.credit.latest_hy_pct !== null
                  ? `${data.credit.latest_hy_pct.toFixed(2)}%`
                  : "—"
              }
              statusKey={data.credit.hy_status}
            />
            <SummaryCard
              title="VIX"
              value={data.vix.latest !== null ? data.vix.latest.toFixed(1) : "—"}
              statusKey={data.vix.status}
            />
          </div>

          <Panel
            title="Yield curve spreads"
            subtitle="Inversão (linhas abaixo de zero) historicamente precede recessão em 6-18 meses (NY Fed model)"
          >
            <YieldCurveChart yc={data.yield_curve} />
          </Panel>

          <Panel
            title="Credit spreads"
            subtitle="HY OAS spike = flight-to-quality em curso. Tight HY (<3%) = froth de crédito."
          >
            <CreditChart credit={data.credit} />
          </Panel>

          <Panel
            title="VIX (volatilidade implícita S&P 500)"
            subtitle="Thresholds: 15 (calmo) · 25 (nervoso) · 40 (medo)"
          >
            <VixChart vix={data.vix} />
          </Panel>

          <Panel
            title="Watchlist"
            subtitle="Último close + variação 1d/30d + P/E + market cap (yfinance daily)"
          >
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                  <th className="py-2 text-left">Ticker</th>
                  <th className="py-2 text-right">Close</th>
                  <th className="py-2 text-right">1d</th>
                  <th className="py-2 text-right">30d</th>
                  <th className="py-2 text-right">P/E</th>
                  <th className="py-2 text-right">Market Cap</th>
                </tr>
              </thead>
              <tbody>
                {data.watchlist.length === 0 && (
                  <tr>
                    <td
                      colSpan={6}
                      className="py-6 text-center text-slate-500"
                    >
                      Watchlist vazia — aguarde o primeiro run do cron
                      quant-yfinance (22:00 UTC).
                    </td>
                  </tr>
                )}
                {data.watchlist.map((w) => (
                  <tr
                    key={w.ticker}
                    className="border-b border-slate-800/50 hover:bg-slate-800/30"
                  >
                    <td className="py-2 font-mono text-slate-200">{w.ticker}</td>
                    <td className="py-2 text-right font-mono">
                      ${w.close.toLocaleString("en-US", { maximumFractionDigits: 2 })}
                    </td>
                    <td
                      className={`py-2 text-right font-mono ${
                        w.change_pct_1d === null
                          ? "text-slate-500"
                          : w.change_pct_1d > 0
                          ? "text-emerald-400"
                          : "text-red-400"
                      }`}
                    >
                      {formatPct(w.change_pct_1d)}
                    </td>
                    <td
                      className={`py-2 text-right font-mono ${
                        w.change_pct_30d === null
                          ? "text-slate-500"
                          : w.change_pct_30d > 0
                          ? "text-emerald-400"
                          : "text-red-400"
                      }`}
                    >
                      {formatPct(w.change_pct_30d)}
                    </td>
                    <td className="py-2 text-right text-slate-300">
                      {w.pe !== null ? w.pe.toFixed(1) : "—"}
                    </td>
                    <td className="py-2 text-right text-slate-300">
                      {formatCap(w.market_cap)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>

          <p className="text-xs text-slate-500">
            Última atualização: {new Date(data.updated_at).toLocaleString("pt-BR")}
          </p>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Small reusable pieces
// ---------------------------------------------------------------------------

function SummaryCard({
  title,
  value,
  statusKey,
}: {
  title: string;
  value: string;
  statusKey: string;
}) {
  return (
    <div className="bg-slate-900 rounded-lg p-5 border border-slate-800">
      <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">
        {title}
      </div>
      <div className="flex items-baseline gap-3 flex-wrap">
        <div className="text-3xl font-bold font-mono">{value}</div>
        <span
          className={`text-xs px-2 py-1 rounded ${
            STATUS_PILL[statusKey] || STATUS_PILL.unknown
          }`}
        >
          {STATUS_LABEL[statusKey] || statusKey}
        </span>
      </div>
    </div>
  );
}

function Panel({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-slate-900 rounded-lg p-5 border border-slate-800">
      <h2 className="font-bold text-slate-100">{title}</h2>
      {subtitle && (
        <p className="text-xs text-slate-500 mt-1 mb-4">{subtitle}</p>
      )}
      {!subtitle && <div className="mb-3" />}
      {children}
    </div>
  );
}

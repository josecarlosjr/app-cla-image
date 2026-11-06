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
import {
  api,
  MacroCountryDetail,
  QuantDashboard,
  QuantMacroRisk,
  QuantSeriesPoint,
} from "../api";

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("pt-BR", { day: "2-digit", month: "short" });
}

function formatDateLong(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("pt-BR", {
    day: "2-digit", month: "short", year: "numeric",
  });
}

function formatPct(v: number | null | undefined): string {
  if (v === null || v === undefined) return "—";
  return `${v > 0 ? "+" : ""}${v.toFixed(2)}%`;
}

// Year-only axis label. The ~7y sparklines can use formatDate, but the
// country-detail charts span 1980-> (~184 quarterly points) where
// "31 mar" is noise and the year is the whole story.
function formatYear(iso: string): string {
  return iso.substring(0, 4);
}

// "2026-03-31" -> "Q1 2026". BIS/Eurostat/BPstat are all quarterly and
// stamped at quarter end, so the quarter is the honest unit to show
// next to a value — not a day that suggests daily precision.
function formatQuarter(iso: string): string {
  const [y, m] = iso.split("-");
  const month = Number(m);
  if (!y || !month) return iso;
  return `Q${Math.ceil(month / 3)} ${y}`;
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

// Merge multiple time series into a single array keyed by ts.
function mergeSeries(
  series: { name: string; data: QuantSeriesPoint[] }[],
): Array<Record<string, number | string>> {
  const map = new Map<string, Record<string, number | string>>();
  for (const { name, data } of series) {
    for (const p of data) {
      const key = p.ts.substring(0, 10);
      if (!map.has(key)) map.set(key, { ts: key });
      map.get(key)![name] = p.value;
    }
  }
  return Array.from(map.values()).sort((a, b) =>
    (a.ts as string).localeCompare(b.ts as string),
  );
}

// ---------------------------------------------------------------------------
// Detector colour bands
// ---------------------------------------------------------------------------

// LPPL bubble probability ∈ [0, 1]
function lpplCellClass(v: number | null): string {
  if (v === null) return "text-slate-500";
  if (v >= 0.85) return "text-red-400 font-semibold";
  if (v >= 0.7) return "text-amber-400";
  if (v >= 0.5) return "text-amber-500/80";
  return "text-slate-400";
}

// GSADF BSADF statistic. PSY 95% critical ≈ 1.49, 99% ≈ 2.07.
function gsadfCellClass(v: number | null, explosive: boolean): string {
  if (v === null) return "text-slate-500";
  if (explosive && v >= 2.07) return "text-red-400 font-semibold";
  if (explosive) return "text-amber-400";
  return "text-slate-400";
}

// ---------------------------------------------------------------------------
// Status styling for the summary cards
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
// Macro-risk status (Phase A integration)
// ---------------------------------------------------------------------------
//
// Credit-to-GDP gap thresholds follow the Basel III countercyclical
// capital buffer (CCyB) convention: gap < 2 % → buffer 0 %, 2-10 →
// buffer rises linearly, > 10 → buffer at maximum (2.5 %). Negative
// gaps mean deleveraging, not a bubble signal.
//
// HPI y-o-y thresholds are heuristic — there is no canonical bubble
// threshold — but 10 %+ is widely flagged as froth in real-estate
// commentary, and < 5 % is normal trend growth.

type Status = { label: string; cls: string; stroke: string };

function creditGapStatus(v: number): Status {
  if (v < 0) {
    return {
      label: "deleveraging",
      cls: "bg-blue-500/20 text-blue-400",
      stroke: "#3b82f6",
    };
  }
  if (v < 2) {
    return {
      label: "abaixo trigger",
      cls: "bg-emerald-500/20 text-emerald-400",
      stroke: "#10b981",
    };
  }
  if (v < 10) {
    return {
      label: "elevado (>trigger CCyB)",
      cls: "bg-amber-500/20 text-amber-400",
      stroke: "#f59e0b",
    };
  }
  return {
    label: "máximo (>10)",
    cls: "bg-red-500/20 text-red-400",
    stroke: "#ef4444",
  };
}

function hpiYoyStatus(v: number | null): Status {
  if (v === null) {
    return {
      label: "—",
      cls: "bg-slate-500/20 text-slate-400",
      stroke: "#64748b",
    };
  }
  if (v < 0) {
    return {
      label: "queda",
      cls: "bg-blue-500/20 text-blue-400",
      stroke: "#3b82f6",
    };
  }
  if (v < 5) {
    return {
      label: "normal",
      cls: "bg-emerald-500/20 text-emerald-400",
      stroke: "#10b981",
    };
  }
  if (v < 10) {
    return {
      label: "elevado",
      cls: "bg-amber-500/20 text-amber-400",
      stroke: "#f59e0b",
    };
  }
  return {
    label: "potencial bolha",
    cls: "bg-red-500/20 text-red-400",
    stroke: "#ef4444",
  };
}

// Friendly labels for the default BPstat series in domain 39.
// 12559646/47 are flagged best-guess in the ingester; if the cron
// log shows a different label, edit here. Unknown ids render as the
// raw numeric id.
const BPSTAT_LABELS: Record<string, string> = {
  "12559645": "Habitação PT — Total (índice)",
  "12559646": "Habitação PT — sibling (novo/existente?)",
  "12559647": "Habitação PT — sibling (novo/existente?)",
  "5739035": "Habitação PT — Total (var. ano-a-ano)",
};

// ---------------------------------------------------------------------------
// Sparkline (Phase B integration)
// ---------------------------------------------------------------------------
//
// Tiny inline line chart for the macro-risk rows. recharts is already
// a dep so no extra payload. Disable animation (jarring inside a
// dense table) and skip axes entirely — the row already shows the
// current value, the sparkline is just for trajectory.

function Sparkline({
  data,
  color,
  width = 90,
  height = 28,
  referenceY,
}: {
  data: QuantSeriesPoint[] | undefined;
  color: string;
  width?: number;
  height?: number;
  referenceY?: number;
}) {
  if (!data || data.length < 2) {
    return <span className="text-slate-600 text-xs">—</span>;
  }
  return (
    <div style={{ width, height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart
          data={data}
          margin={{ top: 2, right: 2, bottom: 2, left: 2 }}
        >
          {referenceY !== undefined && (
            <ReferenceLine
              y={referenceY}
              stroke="#475569"
              strokeDasharray="2 2"
            />
          )}
          <Line
            type="monotone"
            dataKey="value"
            stroke={color}
            dot={false}
            strokeWidth={1.5}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Charts
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
        <XAxis dataKey="ts" tickFormatter={formatDate} stroke="#94a3b8" fontSize={11} />
        <YAxis stroke="#94a3b8" fontSize={11} tickFormatter={(v) => `${Number(v).toFixed(1)}%`} />
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
        <XAxis dataKey="ts" tickFormatter={formatDate} stroke="#94a3b8" fontSize={11} />
        <YAxis stroke="#94a3b8" fontSize={11} tickFormatter={(v) => `${Number(v).toFixed(1)}%`} />
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
        <XAxis dataKey="ts" tickFormatter={formatDate} stroke="#94a3b8" fontSize={11} />
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
// Country detail drawer (Onda 13 multi-pais, Camada B)
// ---------------------------------------------------------------------------
//
// Opened from a row of the BIS credit table. Lives in a right-side
// overlay rather than expanding inline on purpose: the table has to
// stay visible so one country can be read against the others.
//
// Data comes from GET /api/macro/country/{code} on open — the full
// 1980-> history is NOT in the dashboard payload (see MacroCountryDetail
// in api.ts).

const COUNTRY_NAMES: Record<string, string> = {
  AU: "Austrália", BR: "Brasil", CA: "Canadá", CN: "China",
  DE: "Alemanha", ES: "Espanha", FR: "França", GB: "Reino Unido",
  IN: "Índia", IT: "Itália", JP: "Japão", KR: "Coreia do Sul",
  PT: "Portugal", US: "Estados Unidos",
};

// The 2008 marker has to sit on an x value that exists in the data —
// recharts silently draws nothing for a vertical ReferenceLine whose x
// isn't a category in the series. So pick the first observation at or
// after Sep-2008 (Lehman) and use its exact ts; undefined when the
// series doesn't reach 2008, in which case no line is drawn.
function crisisTick(series: QuantSeriesPoint[]): string | undefined {
  const hit = series.find((p) => p.ts.substring(0, 10) >= "2008-09-01");
  return hit?.ts.substring(0, 10);
}

function toChart(series: QuantSeriesPoint[]) {
  return series.map((p) => ({ ts: p.ts.substring(0, 10), value: p.value }));
}

function DrawerChart({
  series,
  color,
  unit,
  refLines,
  crisisTs,
}: {
  series: QuantSeriesPoint[];
  color: string;
  unit: string;
  // `side` is a recharts inside-* position on purpose: an outside label
  // either collides with the Y-axis ticks (left) or is clipped by the
  // container (right) once the text is long enough to be useful.
  refLines?: {
    y: number;
    label: string;
    stroke: string;
    side: "insideTopRight" | "insideBottomLeft" | "insideTopLeft";
  }[];
  crisisTs?: string;
}) {
  const data = toChart(series);
  if (data.length < 2) {
    return (
      <div className="h-[220px] flex items-center justify-center text-sm text-slate-500">
        Série sem dados suficientes.
      </div>
    );
  }
  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={data} margin={{ top: 16, right: 16, bottom: 0, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis
          dataKey="ts"
          tickFormatter={formatYear}
          stroke="#94a3b8"
          fontSize={11}
          minTickGap={28}
        />
        <YAxis
          stroke="#94a3b8"
          fontSize={11}
          tickFormatter={(v) => `${Number(v).toFixed(0)}${unit}`}
        />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          labelFormatter={(l: any) => formatQuarter(String(l))}
          formatter={(v: any) => `${Number(v).toFixed(2)}${unit}`}
        />
        {crisisTs && (
          <ReferenceLine
            x={crisisTs}
            stroke="#ef4444"
            strokeDasharray="4 2"
            label={{
              // A temporal ruler, NOT a peak marker. Each country's
              // credit cycle peaks on its own date — PT's gap tops out
              // at +35.4 in 2001-09 (post-euro expansion), not 2008 —
              // so labelling this "pico" would be wrong for most of
              // the 14. It is here so the countries can be read
              // against one common reference.
              value: "2008 — crise financeira global",
              fill: "#ef4444",
              fontSize: 10,
              position: "top",
            }}
          />
        )}
        {(refLines || []).map((r) => (
          <ReferenceLine
            key={r.label}
            y={r.y}
            stroke={r.stroke}
            strokeDasharray="3 3"
            label={{
              value: r.label,
              fill: r.stroke,
              fontSize: 10,
              position: r.side,
            }}
          />
        ))}
        <Line
          type="monotone"
          dataKey="value"
          stroke={color}
          dot={false}
          strokeWidth={2}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}

function DrawerSection({
  title,
  note,
  children,
}: {
  title: string;
  note?: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <h3 className="text-xs uppercase tracking-wider text-slate-400">
        {title}
      </h3>
      {note && <p className="text-[11px] text-slate-500 mt-0.5 mb-1">{note}</p>}
      <div className="mt-2">{children}</div>
    </div>
  );
}

function CountryDrawer({
  code,
  onClose,
}: {
  code: string;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<MacroCountryDetail | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  // Esc closes. Bound to document (not the panel) so it works before
  // anything inside has focus.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError("");
    setDetail(null);
    api
      .get<MacroCountryDetail>(`/macro/country/${code}`)
      .then((r) => {
        if (alive) setDetail(r.data);
      })
      .catch((e: any) => {
        if (alive) {
          setError(
            e?.response?.data?.detail || e?.message || "erro desconhecido",
          );
        }
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [code]);

  const gap = detail?.credit_gap ?? null;
  const ratio = detail?.credit_ratio ?? null;
  const crisisTs = gap ? crisisTick(gap.series) : undefined;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop — click outside closes. */}
      <div
        className="absolute inset-0 bg-slate-950/70"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`Detalhe macro ${code}`}
        className="relative h-full w-full max-w-2xl bg-slate-900 border-l border-slate-800 overflow-y-auto shadow-2xl"
      >
        <div className="sticky top-0 bg-slate-900/95 backdrop-blur border-b border-slate-800 px-5 py-4 flex items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-bold text-slate-100">
              {COUNTRY_NAMES[code] || code}{" "}
              <span className="font-mono text-slate-500 text-sm">{code}</span>
            </h2>
            <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-sm">
              {gap && (
                <span className="font-mono text-slate-200">
                  gap {gap.value > 0 ? "+" : ""}
                  {gap.value.toFixed(2)}%
                  <span className="text-slate-500 text-xs ml-1">
                    ({formatQuarter(gap.ts)})
                  </span>
                </span>
              )}
              {ratio && (
                <span className="font-mono text-slate-200">
                  ratio {ratio.value.toFixed(2)}%
                  <span className="text-slate-500 text-xs ml-1">
                    ({formatQuarter(ratio.ts)})
                  </span>
                </span>
              )}
              {!loading && !gap && !ratio && !error && (
                <span className="text-slate-500 text-xs">
                  Sem dados BIS para este país.
                </span>
              )}
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Fechar"
            className="text-slate-400 hover:text-slate-100 text-xl leading-none px-2 shrink-0"
          >
            ×
          </button>
        </div>

        <div className="px-5 py-5 space-y-7">
          {loading && (
            <div className="h-40 flex items-center justify-center text-sm text-slate-500">
              Carregando série completa…
            </div>
          )}

          {error && (
            <div className="bg-red-500/10 border border-red-500/40 rounded-lg p-3 text-sm text-red-400">
              Erro ao carregar o detalhe: {error}
            </div>
          )}

          {detail && (
            <>
              <DrawerSection
                title="Credit-to-GDP gap (BIS)"
                note="Desvio, em pontos percentuais do PIB, face à tendência HP-filtrada do crédito. Série completa."
              >
                {gap ? (
                  <DrawerChart
                    series={gap.series}
                    color="#f59e0b"
                    unit="%"
                    crisisTs={crisisTs}
                    refLines={[
                      {
                        y: 2,
                        label: "+2% trigger CCyB (Basel III)",
                        stroke: "#ef4444",
                        side: "insideTopRight",
                      },
                      {
                        y: 0,
                        label: "0 = tendência de longo prazo",
                        stroke: "#64748b",
                        side: "insideBottomLeft",
                      },
                    ]}
                  />
                ) : (
                  <p className="text-sm text-slate-500">Sem dados.</p>
                )}
              </DrawerSection>

              <DrawerSection
                title="Credit-to-GDP ratio (BIS)"
                note="Nível absoluto do crédito ao setor privado não financeiro em % do PIB — não um desvio."
              >
                {ratio ? (
                  <DrawerChart
                    series={ratio.series}
                    color="#3b82f6"
                    unit="%"
                    crisisTs={crisisTs}
                  />
                ) : (
                  <p className="text-sm text-slate-500">Sem dados.</p>
                )}
              </DrawerSection>

              {detail.hpi && (
                <DrawerSection
                  title="House Price Index (Eurostat, 2015=100)"
                  note={`Nível do índice. Variação homóloga mais recente: ${formatPct(
                    detail.hpi.yoy_pct,
                  )} (${formatQuarter(detail.hpi.ts)}).`}
                >
                  <DrawerChart
                    series={detail.hpi.series}
                    color="#10b981"
                    unit=""
                    refLines={[
                      {
                        y: 100,
                        label: "2015=100",
                        stroke: "#64748b",
                        side: "insideBottomLeft",
                      },
                    ]}
                  />
                </DrawerSection>
              )}

              {detail.bpstat.map((b) => (
                <DrawerSection
                  key={b.series_id}
                  title={`BPstat — ${b.label}`}
                  note={`Banco de Portugal, série ${b.series_id}. Último: ${b.value.toFixed(
                    2,
                  )}${b.unit} (${formatQuarter(b.ts)}).`}
                >
                  <DrawerChart
                    series={b.series}
                    color="#8b5cf6"
                    unit={b.unit}
                    refLines={
                      // A rate series (unit "%") crosses zero, and zero
                      // is the line that matters; an index level does
                      // not, so it gets no reference line.
                      b.unit === "%"
                        ? [{
                            y: 0,
                            label: "0% (sem variação)",
                            stroke: "#64748b",
                            side: "insideBottomLeft" as const,
                          }]
                        : undefined
                    }
                  />
                </DrawerSection>
              ))}

              <p className="text-[11px] leading-relaxed text-slate-500 border-t border-slate-800 pt-4">
                O credit-to-GDP gap é o desvio face a uma tendência
                HP-filtrada. Foi desenhado para detetar EXCESSO (gaps
                positivos &gt;2% = trigger Basel III). Gaps muito negativos
                refletem desalavancagem e o endpoint bias do filtro HP — não
                medem segurança. BIS: dados trimestrais, publicação T+90.
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Macro-risk panel (Phase A integration + Phase B sparklines)
// ---------------------------------------------------------------------------

function MacroRiskPanel({ data }: { data: QuantMacroRisk }) {
  // Which country's detail drawer is open, if any. Kept here (not on the
  // page) so the diff stays local; the drawer itself is `fixed`/z-50 so
  // it escapes the panel's layout regardless.
  const [openCountry, setOpenCountry] = useState<string | null>(null);
  const closeDrawer = useCallback(() => setOpenCountry(null), []);

  const creditEntries = Object.entries(data.credit_gap).sort();
  const hpiEntries = Object.entries(data.hpi).sort();
  const bpstatEntries = Object.entries(data.bpstat).sort();

  const isEmpty =
    creditEntries.length === 0 &&
    hpiEntries.length === 0 &&
    bpstatEntries.length === 0;

  if (isEmpty) {
    return (
      <Panel
        title="Risco macro / imobiliário"
        subtitle="BIS credit-to-GDP gap + Eurostat HPI + BPstat. Atualização semanal (segundas, 05:00–06:00 UTC)."
      >
        <div className="h-32 flex items-center justify-center text-sm text-slate-500">
          Sem dados ainda — aguarde o primeiro run dos crons quant-bis /
          quant-eurostat / quant-bpstat.
        </div>
      </Panel>
    );
  }

  return (
    <Panel
      title="Risco macro / imobiliário"
      subtitle="BIS credit-to-GDP gap (>2% = trigger CCyB Basel III, >10% = máximo histórico) + Eurostat HPI / BPstat (índice 2015=100 + variação a/a). Sparkline = últimos ~7 anos."
    >
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {creditEntries.length > 0 && (
          <div>
            <h3 className="text-xs uppercase tracking-wider text-slate-400 mb-2">
              Credit-to-GDP gap (BIS)
              <span className="normal-case tracking-normal text-slate-500 ml-2">
                — clique num país para a série completa
              </span>
            </h3>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                  <th className="py-2 text-left">País</th>
                  <th className="py-2 text-right">Gap %</th>
                  <th className="py-2 text-center">Trajetória</th>
                  <th className="py-2 text-right">Status</th>
                </tr>
              </thead>
              <tbody>
                {creditEntries.map(([country, rec]) => {
                  const status = creditGapStatus(rec.value);
                  return (
                    <tr
                      key={country}
                      onClick={() => setOpenCountry(country)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          setOpenCountry(country);
                        }
                      }}
                      tabIndex={0}
                      role="button"
                      aria-label={`Abrir detalhe de ${country}`}
                      className="border-b border-slate-800/50 hover:bg-slate-800/30 cursor-pointer focus:outline-none focus:bg-slate-800/50"
                    >
                      <td className="py-2 font-mono text-slate-200">
                        {country}
                      </td>
                      <td className="py-2 text-right font-mono">
                        {rec.value > 0 ? "+" : ""}
                        {rec.value.toFixed(2)}%
                      </td>
                      <td className="py-2">
                        <div className="flex justify-center">
                          <Sparkline
                            data={rec.series}
                            color={status.stroke}
                            referenceY={0}
                          />
                        </div>
                      </td>
                      <td className="py-2 text-right">
                        <span className={`text-xs px-2 py-0.5 rounded ${status.cls}`}>
                          {status.label}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {hpiEntries.length > 0 && (
          <div>
            <h3 className="text-xs uppercase tracking-wider text-slate-400 mb-2">
              House Price Index (Eurostat, 2015=100)
            </h3>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                  <th className="py-2 text-left">Geo</th>
                  <th className="py-2 text-right">Nível</th>
                  <th className="py-2 text-right">Var. a/a</th>
                  <th className="py-2 text-center">Trajetória</th>
                  <th className="py-2 text-right">Status</th>
                </tr>
              </thead>
              <tbody>
                {hpiEntries.map(([geo, rec]) => {
                  const status = hpiYoyStatus(rec.yoy_pct);
                  return (
                    <tr
                      key={geo}
                      className="border-b border-slate-800/50 hover:bg-slate-800/30"
                    >
                      <td className="py-2 font-mono text-slate-200">{geo}</td>
                      <td className="py-2 text-right font-mono">
                        {rec.value.toFixed(1)}
                      </td>
                      <td className="py-2 text-right font-mono">
                        {formatPct(rec.yoy_pct)}
                      </td>
                      <td className="py-2">
                        <div className="flex justify-center">
                          <Sparkline
                            data={rec.series}
                            color={status.stroke}
                          />
                        </div>
                      </td>
                      <td className="py-2 text-right">
                        <span className={`text-xs px-2 py-0.5 rounded ${status.cls}`}>
                          {status.label}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {bpstatEntries.length > 0 && (
        <div className="mt-6">
          <h3 className="text-xs uppercase tracking-wider text-slate-400 mb-2">
            BPstat — imobiliário PT granular (Banco de Portugal)
          </h3>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                <th className="py-2 text-left">Série</th>
                <th className="py-2 text-right">Valor</th>
                <th className="py-2 text-right">Var. a/a</th>
                <th className="py-2 text-center">Trajetória</th>
                <th className="py-2 text-right">Último</th>
              </tr>
            </thead>
            <tbody>
              {bpstatEntries.map(([sid, rec]) => {
                const status = hpiYoyStatus(rec.yoy_pct);
                return (
                  <tr
                    key={sid}
                    className="border-b border-slate-800/50 hover:bg-slate-800/30"
                  >
                    <td className="py-2 text-slate-200">
                      {BPSTAT_LABELS[sid] || (
                        <span className="font-mono text-slate-400">{sid}</span>
                      )}
                    </td>
                    <td className="py-2 text-right font-mono">
                      {rec.value.toFixed(2)}
                    </td>
                    <td className="py-2 text-right font-mono text-slate-300">
                      {formatPct(rec.yoy_pct)}
                    </td>
                    <td className="py-2">
                      <div className="flex justify-center">
                        <Sparkline
                          data={rec.series}
                          color={status.stroke}
                        />
                      </div>
                    </td>
                    <td className="py-2 text-right text-slate-500 text-xs">
                      {formatDateLong(rec.ts)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {openCountry && (
        <CountryDrawer code={openCountry} onClose={closeDrawer} />
      )}
    </Panel>
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
            Indicadores macro, cross-asset e detectores de bolha (LPPL + GSADF).
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

          {data.macro_risk && <MacroRiskPanel data={data.macro_risk} />}

          <Panel
            title="Watchlist + bubble detectors"
            subtitle="Close + variação + valuação + LPPL bubble prob (Sornette) + GSADF explosivity test (Phillips-Shi-Yu). Detectores correm 1×/dia às 23:00 UTC."
          >
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                  <th className="py-2 text-left">Ticker</th>
                  <th className="py-2 text-right">Close</th>
                  <th className="py-2 text-right">1d</th>
                  <th className="py-2 text-right">30d</th>
                  <th className="py-2 text-right">P/E</th>
                  <th className="py-2 text-right">Mkt Cap</th>
                  <th className="py-2 text-right" title="LPPL bubble probability (0..1) — R² of best log-periodic fit, discounted if params outside Sornette ranges">LPPL</th>
                  <th className="py-2 text-right" title="GSADF BSADF statistic. PSY 95% critical ≈ 1.49, 99% ≈ 2.07. Values above 1.49 = mildly explosive.">GSADF</th>
                </tr>
              </thead>
              <tbody>
                {data.watchlist.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-6 text-center text-slate-500">
                      Watchlist vazia — aguarde o primeiro run do cron quant-yfinance (22:00 UTC).
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
                    <td className={`py-2 text-right font-mono ${lpplCellClass(w.lppl_bubble_prob)}`}>
                      {w.lppl_bubble_prob !== null ? w.lppl_bubble_prob.toFixed(2) : "—"}
                    </td>
                    <td className={`py-2 text-right font-mono ${gsadfCellClass(w.gsadf_bsadf, w.gsadf_explosive)}`}>
                      {w.gsadf_bsadf !== null ? w.gsadf_bsadf.toFixed(2) : "—"}
                      {w.gsadf_explosive && (
                        <span className="ml-1" title="Above 95% critical">⚠</span>
                      )}
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

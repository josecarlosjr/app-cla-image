import { useState } from "react";
import { api } from "../api";

// Local types — the Bubble Engine surface (Onda 13) is kept out of the
// shared api.ts until it stabilises.
type BubbleSignal = {
  name: string;
  score: number;
  confidence: number;
  detail: string;
};

type CaseResult = {
  name: string;
  expectation: string;
  pass: boolean;
  result: {
    composite: number;
    aggregate_confidence: number;
    coverage: number;
    n_signals_used: number;
    n_signals_total: number;
    flagged: boolean;
    components: BubbleSignal[];
  };
};

type SelfTestReport = {
  suite: string;
  step: string;
  passed: number;
  total: number;
  all_pass: boolean;
  weights: Record<string, number>;
  flag_rule: { min_composite: number; min_confidence: number };
  cases: CaseResult[];
};

// --- Step 2 orchestrator: live per-ticker scores -----------------------
type ScoreRow = {
  ticker: string;
  composite: number;
  aggregate_confidence: number;
  coverage: number;
  n_signals_used: number;
  n_signals_total: number;
  flagged: boolean;
  components: BubbleSignal[];
  context?: {
    close: number | null;
    change_pct_30d: number | null;
    pe?: number | null;
    gsadf_explosive: boolean;
  };
};

type ScoresReport = {
  engine: string;
  step: string;
  scope: string;
  alerting_enabled: boolean;
  alerting_note: string;
  weights: Record<string, number>;
  flag_rule: { min_composite: number; min_confidence: number };
  n_tickers: number;
  n_flagged: number;
  generated_at: string;
  tickers: ScoreRow[];
};

const SIGNALS: { name: string; label: string; title: string }[] = [
  { name: "momentum", label: "Mom.", title: "momentum — LPPL sobre o preço" },
  { name: "temporal", label: "Temp.", title: "temporal — aceleração de notícias" },
  { name: "graph_fragility", label: "Graph", title: "graph_fragility — superfície de contágio no grafo" },
  { name: "valuation", label: "Val.", title: "valuation — múltiplo (P/E; CAPE quando houver)" },
  { name: "credit", label: "Cred.", title: "credit — BIS credit-to-GDP gap (pano de fundo macro)" },
];

function signal(row: ScoreRow, name: string): BubbleSignal | undefined {
  return row.components.find((c) => c.name === name);
}

export default function BubbleEngine() {
  const [report, setReport] = useState<SelfTestReport | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [ranAt, setRanAt] = useState<string>("");
  const [copied, setCopied] = useState(false);

  const [scores, setScores] = useState<ScoresReport | null>(null);
  const [scoresError, setScoresError] = useState("");
  const [scoresLoading, setScoresLoading] = useState(false);

  async function run() {
    setLoading(true);
    setError("");
    setCopied(false);
    try {
      const resp = await api.get<SelfTestReport>("/bubble/selftest");
      setReport(resp.data);
      setRanAt(new Date().toLocaleString("pt-BR"));
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || "erro desconhecido");
    } finally {
      setLoading(false);
    }
  }

  async function runScores() {
    setScoresLoading(true);
    setScoresError("");
    try {
      const resp = await api.get<ScoresReport>("/bubble/scores");
      setScores(resp.data);
    } catch (e: any) {
      setScoresError(
        e?.response?.data?.detail || e?.message || "erro desconhecido",
      );
    } finally {
      setScoresLoading(false);
    }
  }

  async function copyJson() {
    if (!report) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard blocked — the <pre> below is still selectable
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold">Bubble Engine</h1>
          <p className="text-slate-400 mt-1 max-w-3xl">
            Onda 13. <b>Scores ao vivo</b> combina, por ticker, momentum
            (preço/LPPL), temporal (aceleração de notícias) e fragilidade de
            grafo (knowledge graph) no composto ponderado por confiança. O{" "}
            <b>self-test</b> valida a matemática com cenários sintéticos.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={runScores}
            disabled={scoresLoading}
            className="px-4 py-2 bg-primary-500 hover:bg-primary-600 disabled:opacity-50 rounded-lg text-sm font-medium transition"
          >
            {scoresLoading ? "Calculando..." : "Scores ao vivo"}
          </button>
          <button
            onClick={run}
            disabled={loading}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 rounded-lg text-sm font-medium transition"
          >
            {loading ? "Rodando..." : "Self-test"}
          </button>
        </div>
      </div>

      {/* ---------------- Live scores (Step 2 orchestrator) ------------- */}
      {scoresError && (
        <div className="bg-red-500/10 border border-red-500/40 rounded-lg p-4 text-sm text-red-400">
          Erro ao calcular scores: {scoresError}
        </div>
      )}

      {scores && (
        <div className="space-y-4">
          <div className="rounded-lg p-4 border bg-amber-500/10 border-amber-500/40">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <span className="text-sm font-medium text-amber-300">
                Scores informativos — alertas automáticos DESATIVADOS
              </span>
              <span className="text-xs text-slate-400">
                {scores.n_flagged}/{scores.n_tickers} cruzariam o limiar ·
                gerado {new Date(scores.generated_at).toLocaleString("pt-BR")}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">{scores.alerting_note}</p>
          </div>

          <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                  <th className="py-2 px-4 text-left">Ticker</th>
                  <th className="py-2 px-2 text-right">Composite</th>
                  <th className="py-2 px-2 text-right">Confiança</th>
                  <th className="py-2 px-2 text-right">Cobertura</th>
                  {SIGNALS.map((s) => (
                    <th
                      key={s.name}
                      className="py-2 px-2 text-right"
                      title={s.title}
                    >
                      {s.label}
                    </th>
                  ))}
                  <th className="py-2 px-3 text-center">Flag</th>
                </tr>
              </thead>
              <tbody>
                {scores.tickers.map((row) => (
                  <tr
                    key={row.ticker}
                    className={`border-b border-slate-800/50 ${
                      row.flagged ? "bg-red-500/5" : ""
                    }`}
                  >
                    <td className="py-2 px-4">
                      <div className="font-mono font-bold text-slate-100">
                        {row.ticker}
                      </div>
                      {row.context && (
                        <div className="text-xs text-slate-500">
                          {row.context.change_pct_30d != null
                            ? `${row.context.change_pct_30d >= 0 ? "+" : ""}${row.context.change_pct_30d.toFixed(1)}% 30d`
                            : "—"}
                          {row.context.gsadf_explosive && (
                            <span className="ml-1 text-red-400" title="GSADF explosivo">
                              ⚡
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                    <td
                      className={`py-2 px-2 text-right font-mono font-bold ${
                        row.flagged ? "text-red-400" : "text-slate-200"
                      }`}
                    >
                      {row.composite.toFixed(2)}
                    </td>
                    <td
                      className={`py-2 px-2 text-right font-mono ${
                        row.aggregate_confidence < scores.flag_rule.min_confidence
                          ? "text-slate-500"
                          : "text-slate-200"
                      }`}
                    >
                      {row.aggregate_confidence.toFixed(2)}
                    </td>
                    <td className="py-2 px-2 text-right font-mono text-slate-400">
                      {row.n_signals_used}/{row.n_signals_total}
                    </td>
                    {SIGNALS.map(({ name }) => {
                      const s = signal(row, name);
                      const abstain = !s || s.confidence === 0;
                      return (
                        <td
                          key={name}
                          className={`py-2 px-2 text-right font-mono ${
                            abstain ? "text-slate-600" : "text-slate-300"
                          }`}
                          title={s ? `${s.detail} (conf ${s.confidence.toFixed(2)})` : "sem dados"}
                        >
                          {abstain ? "—" : s!.score.toFixed(2)}
                        </td>
                      );
                    })}
                    <td className="py-2 px-3 text-center">
                      <span
                        className={`text-xs px-2 py-0.5 rounded ${
                          row.flagged
                            ? "bg-red-500/20 text-red-400"
                            : "bg-slate-700/40 text-slate-500"
                        }`}
                      >
                        {row.flagged ? "⚠" : "—"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-slate-500">
            Composite = média ponderada por confiança; Flag exige composite ≥{" "}
            {scores.flag_rule.min_composite.toFixed(2)} <b>e</b> confiança ≥{" "}
            {scores.flag_rule.min_confidence.toFixed(2)} (um sinal sozinho nunca
            dispara). Pesos placeholder até o backtest calibrar. Passe o mouse
            num score para ver o detalhe.
          </p>
        </div>
      )}

      {/* ---------------- Self-test (Step 1.5) -------------------------- */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/40 rounded-lg p-4 text-sm text-red-400">
          Erro ao rodar self-test: {error}
        </div>
      )}

      {!report && !scores && !error && !scoresError && !loading && !scoresLoading && (
        <div className="text-slate-500 text-sm">
          “Scores ao vivo” calcula o composto por ticker com dados reais.
          “Self-test” valida a matemática com cenários sintéticos (copie o JSON
          e cole de volta no chat para análise).
        </div>
      )}

      {report && (
        <>
          <div className="pt-2">
            <h2 className="text-xl font-bold text-slate-200">
              Self-test — Passo 1.5
            </h2>
          </div>
          <div
            className={`rounded-lg p-4 border flex items-center justify-between ${
              report.all_pass
                ? "bg-emerald-500/10 border-emerald-500/40"
                : "bg-red-500/10 border-red-500/40"
            }`}
          >
            <div>
              <span className="text-lg font-bold">
                {report.passed}/{report.total} casos passaram
              </span>
              <span
                className={`ml-3 text-sm ${
                  report.all_pass ? "text-emerald-400" : "text-red-400"
                }`}
              >
                {report.all_pass ? "✓ tudo verde" : "✗ há falhas — ver casos"}
              </span>
            </div>
            {ranAt && (
              <span className="text-xs text-slate-500">rodado {ranAt}</span>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-slate-900 rounded-lg p-5 border border-slate-800">
              <h2 className="font-bold text-slate-100">Pesos atuais</h2>
              <p className="text-xs text-slate-500 mt-1 mb-3">
                PLACEHOLDER — sem dataset rotulado, pesos hand-set. Sinais
                com peso 0 ainda não existem (Step 2+).
              </p>
              <div className="flex flex-wrap gap-2">
                {Object.entries(report.weights).map(([k, v]) => (
                  <span
                    key={k}
                    className={`text-xs px-2 py-1 rounded font-mono ${
                      v > 0
                        ? "bg-slate-800 text-slate-200"
                        : "bg-slate-800/40 text-slate-500"
                    }`}
                  >
                    {k}: {v.toFixed(2)}
                  </span>
                ))}
              </div>
            </div>

            <div className="bg-slate-900 rounded-lg p-5 border border-slate-800">
              <h2 className="font-bold text-slate-100">Regra de disparo</h2>
              <p className="text-xs text-slate-500 mt-1 mb-3">
                Dispara alerta só quando composite E aggregate_confidence
                cruzam os limiares — um sinal sozinho nunca dispara.
              </p>
              <div className="flex flex-wrap gap-2 text-xs font-mono">
                <span className="bg-slate-800 text-slate-200 px-2 py-1 rounded">
                  composite ≥ {report.flag_rule.min_composite.toFixed(2)}
                </span>
                <span className="bg-slate-800 text-slate-200 px-2 py-1 rounded">
                  confiança ≥ {report.flag_rule.min_confidence.toFixed(2)}
                </span>
              </div>
            </div>
          </div>

          {report.cases.map((c) => (
            <div
              key={c.name}
              className="bg-slate-900 rounded-lg p-5 border border-slate-800"
            >
              <div className="flex items-center gap-3 mb-2 flex-wrap">
                <span className="font-mono font-bold text-slate-100">
                  {c.name}
                </span>
                <span
                  className={`text-xs px-2 py-0.5 rounded ${
                    c.pass
                      ? "bg-emerald-500/20 text-emerald-400"
                      : "bg-red-500/20 text-red-400"
                  }`}
                >
                  {c.pass ? "PASS" : "FAIL"}
                </span>
                <span
                  className={`text-xs px-2 py-0.5 rounded ${
                    c.result.flagged
                      ? "bg-red-500/20 text-red-400"
                      : "bg-slate-700/40 text-slate-400"
                  }`}
                >
                  {c.result.flagged ? "⚠ dispararia" : "não dispara"}
                </span>
              </div>
              <p className="text-xs text-slate-500 mb-3">
                esperado: {c.expectation}
              </p>
              <div className="flex gap-6 mb-3 text-sm flex-wrap">
                <div>
                  <span className="text-slate-400">composite </span>
                  <span className="font-mono font-bold">
                    {c.result.composite.toFixed(3)}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400">confiança </span>
                  <span className="font-mono font-bold">
                    {c.result.aggregate_confidence.toFixed(3)}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400">coverage </span>
                  <span className="font-mono">
                    {c.result.n_signals_used}/{c.result.n_signals_total}
                  </span>
                </div>
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                    <th className="py-1 text-left">Sinal</th>
                    <th className="py-1 text-right">Score</th>
                    <th className="py-1 text-right">Conf.</th>
                    <th className="py-1 text-left pl-4">Detalhe</th>
                  </tr>
                </thead>
                <tbody>
                  {c.result.components.map((s) => (
                    <tr key={s.name} className="border-b border-slate-800/50">
                      <td className="py-1 font-mono text-slate-300">{s.name}</td>
                      <td className="py-1 text-right font-mono">
                        {s.score.toFixed(2)}
                      </td>
                      <td
                        className={`py-1 text-right font-mono ${
                          s.confidence === 0 ? "text-slate-600" : "text-slate-300"
                        }`}
                      >
                        {s.confidence.toFixed(2)}
                      </td>
                      <td className="py-1 pl-4 text-slate-500 text-xs">
                        {s.detail}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}

          <div className="bg-slate-900 rounded-lg p-5 border border-slate-800">
            <div className="flex items-center justify-between mb-3">
              <h2 className="font-bold text-slate-100">
                JSON bruto (copie e cole de volta para análise)
              </h2>
              <button
                onClick={copyJson}
                className="px-3 py-1 text-xs bg-slate-800 hover:bg-slate-700 rounded transition"
              >
                {copied ? "Copiado!" : "Copiar JSON"}
              </button>
            </div>
            <pre className="text-xs text-slate-300 bg-slate-950 rounded p-3 overflow-auto max-h-96 whitespace-pre-wrap">
              {JSON.stringify(report, null, 2)}
            </pre>
          </div>
        </>
      )}
    </div>
  );
}

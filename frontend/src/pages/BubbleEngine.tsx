import { useState } from "react";
import { api } from "../api";

// Local types — the self-test endpoint is Onda 13 only, kept out of
// the shared api.ts until the engine surface stabilises.
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

export default function BubbleEngine() {
  const [report, setReport] = useState<SelfTestReport | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [ranAt, setRanAt] = useState<string>("");
  const [copied, setCopied] = useState(false);

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
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold">Bubble Engine — Self-test</h1>
          <p className="text-slate-400 mt-1">
            Onda 13 · Passo 1.5. Valida a matemática de scoring (contrato
            Signal + composto + aggregate_confidence + regra de disparo)
            com cenários sintéticos. Sem DB, sem LLM — determinístico.
          </p>
        </div>
        <button
          onClick={run}
          disabled={loading}
          className="px-4 py-2 bg-primary-500 hover:bg-primary-600 disabled:opacity-50 rounded-lg text-sm font-medium transition"
        >
          {loading ? "Rodando..." : "Rodar self-test"}
        </button>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/40 rounded-lg p-4 text-sm text-red-400">
          Erro ao rodar self-test: {error}
        </div>
      )}

      {!report && !error && !loading && (
        <div className="text-slate-500 text-sm">
          Clique em “Rodar self-test” para gerar o relatório. Depois use
          “Copiar JSON” e cole de volta no chat para análise.
        </div>
      )}

      {report && (
        <>
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

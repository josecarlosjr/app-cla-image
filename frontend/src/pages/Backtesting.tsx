import { useEffect, useState } from "react";
import {
  api, BacktestResult, BacktestRun, QualityMetrics, SystemSnapshot,
} from "../api";

const SNAPSHOT_LABELS: Record<string, string> = {
  trends: "Trends",
  cross_pillar: "Cross-Pillar",
  supply_chain: "Supply Chain",
  graph: "Knowledge Graph",
};

export default function Backtesting() {
  const [daysBack, setDaysBack] = useState(30);
  const [stepHours, setStepHours] = useState(24);
  const [running, setRunning] = useState(false);
  const [latest, setLatest] = useState<BacktestResult | null>(null);
  const [runs, setRuns] = useState<BacktestRun[]>([]);
  const [snapshots, setSnapshots] = useState<SystemSnapshot[]>([]);
  const [quality, setQuality] = useState<QualityMetrics | null>(null);
  const [capturing, setCapturing] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");

  const loadAll = async () => {
    try {
      const [r, s, q] = await Promise.all([
        api.get("/backtest/runs", { params: { limit: 10 } }),
        api.get("/snapshots", { params: { days: 30, limit: 30 } }),
        api.get<QualityMetrics>("/metrics/quality", { params: { days: 90 } }),
      ]);
      setRuns(r.data.runs || []);
      setSnapshots(s.data.snapshots || []);
      setQuality(q.data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  const handleRun = async () => {
    setRunning(true);
    setStatusMsg("");
    try {
      const res = await api.post<BacktestResult>("/backtest/run", {
        days_back: daysBack,
        eval_step_hours: stepHours,
        pattern_lookback_hours: 48,
      });
      setLatest(res.data);
      await loadAll();
      setStatusMsg(`Run #${res.data.run_id} concluido — ${res.data.summary.tick_count} ticks`);
    } catch (e: any) {
      const detail = e?.response?.data?.detail || e?.message || "erro desconhecido";
      setStatusMsg(`Erro ao rodar backtest: ${detail}`);
      console.error(e);
    } finally {
      setRunning(false);
    }
  };

  const handleCapture = async () => {
    setCapturing(true);
    setStatusMsg("");
    try {
      const res = await api.post<{ captured: Record<string, number> }>("/snapshots/capture");
      const types = Object.keys(res.data.captured).join(", ");
      setStatusMsg(`Snapshots capturados: ${types}`);
      await loadAll();
    } catch (e: any) {
      const detail = e?.response?.data?.detail || e?.message || "erro desconhecido";
      setStatusMsg(`Erro ao capturar snapshot: ${detail}`);
      console.error(e);
    } finally {
      setCapturing(false);
    }
  };

  const ticks = latest?.ticks || (runs[0]?.result.ticks ?? []);
  const summary = latest?.summary || runs[0]?.result.summary;
  const maxArticles = Math.max(1, ...ticks.map((t) => t.articles_visible));
  const maxPatterns = Math.max(1, ...ticks.map((t) => t.patterns_visible));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Backtesting</h1>
        <p className="text-slate-400 mt-1">
          Replay historico do sistema, snapshots e metricas de qualidade
        </p>
      </div>

      <div className="bg-slate-900 rounded-lg border border-slate-800 p-5 space-y-4">
        <div className="flex flex-wrap items-end gap-4">
          <div>
            <label className="text-xs text-slate-400 block mb-1">Janela (dias)</label>
            <input
              type="number"
              value={daysBack}
              onChange={(e) => setDaysBack(parseInt(e.target.value) || 1)}
              min={1}
              max={365}
              className="bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm w-24"
            />
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Passo (horas)</label>
            <input
              type="number"
              value={stepHours}
              onChange={(e) => setStepHours(parseInt(e.target.value) || 1)}
              min={1}
              max={168}
              className="bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm w-24"
            />
          </div>
          <button
            onClick={handleRun}
            disabled={running}
            className="px-4 py-1.5 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 rounded text-sm font-medium transition"
          >
            {running ? "Rodando..." : "Rodar Backtest"}
          </button>
          <button
            onClick={handleCapture}
            disabled={capturing}
            className="px-4 py-1.5 bg-slate-700 hover:bg-slate-600 disabled:opacity-50 rounded text-sm font-medium transition"
          >
            {capturing ? "Capturando..." : "Capturar Snapshot"}
          </button>
        </div>
        {statusMsg && (
          <div className="text-sm text-emerald-400">{statusMsg}</div>
        )}
      </div>

      {summary && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-slate-900 rounded-lg p-4 border border-slate-800">
            <div className="text-2xl font-bold">{summary.tick_count}</div>
            <div className="text-xs text-slate-400 mt-1">Ticks avaliados</div>
          </div>
          <div className="bg-slate-900 rounded-lg p-4 border border-slate-800">
            <div className="text-2xl font-bold text-blue-400">
              {summary.total_articles_observed}
            </div>
            <div className="text-xs text-slate-400 mt-1">Artigos observados</div>
          </div>
          <div className="bg-slate-900 rounded-lg p-4 border border-slate-800">
            <div className="text-2xl font-bold text-emerald-400">
              {summary.total_patterns_observed}
            </div>
            <div className="text-xs text-slate-400 mt-1">Patterns visiveis</div>
          </div>
          <div className="bg-slate-900 rounded-lg p-4 border border-slate-800">
            <div className="text-2xl font-bold text-amber-400">
              {summary.total_chains_observed}
            </div>
            <div className="text-xs text-slate-400 mt-1">Chains visiveis</div>
          </div>
        </div>
      )}

      {ticks.length > 0 && (
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-5">
          <h2 className="text-sm uppercase tracking-wider text-slate-400 mb-4">
            Replay timeline
          </h2>
          <div className="space-y-2">
            {ticks.map((t) => (
              <div key={t.at} className="flex items-center gap-3 text-xs">
                <div className="w-32 text-slate-400 font-mono">
                  {new Date(t.at).toLocaleString("pt-BR", {
                    month: "short",
                    day: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </div>
                <div className="flex-1 flex items-center gap-2">
                  <div
                    className="h-4 bg-blue-600/40 rounded"
                    style={{ width: `${(t.articles_visible / maxArticles) * 60}%` }}
                    title={`${t.articles_visible} artigos`}
                  />
                  <span className="text-slate-400">{t.articles_visible}</span>
                </div>
                <div className="flex-1 flex items-center gap-2">
                  <div
                    className="h-4 bg-emerald-600/40 rounded"
                    style={{ width: `${(t.patterns_visible / maxPatterns) * 60}%` }}
                    title={`${t.patterns_visible} patterns`}
                  />
                  <span className="text-slate-400">{t.patterns_visible}</span>
                </div>
                <div className="w-12 text-right text-amber-400">
                  {t.chains_visible > 0 ? `🔗 ${t.chains_visible}` : "—"}
                </div>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-6 mt-4 text-xs text-slate-500">
            <span><span className="inline-block w-3 h-3 bg-blue-600/40 rounded mr-1" />Artigos</span>
            <span><span className="inline-block w-3 h-3 bg-emerald-600/40 rounded mr-1" />Patterns</span>
            <span>🔗 Chains cross-pillar</span>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-5">
          <h2 className="text-sm uppercase tracking-wider text-slate-400 mb-4">
            Quality metrics ({quality?.window_days || 90}d)
          </h2>
          {quality && Object.keys(quality.by_type).length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                  <th className="py-2 text-left">Tipo</th>
                  <th className="py-2 text-right">TP</th>
                  <th className="py-2 text-right">FP</th>
                  <th className="py-2 text-right">Precisao</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(quality.by_type).map(([type, m]) => (
                  <tr key={type} className="border-b border-slate-800/50">
                    <td className="py-2 font-medium">{type}</td>
                    <td className="py-2 text-right text-emerald-400">{m.true_positive}</td>
                    <td className="py-2 text-right text-red-400">{m.false_positive}</td>
                    <td className="py-2 text-right">
                      {m.precision != null ? `${(m.precision * 100).toFixed(0)}%` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-sm text-slate-500">
              Marque outcomes de eventos (TP/FP) para ver precisao acumulada
            </p>
          )}
        </div>

        <div className="bg-slate-900 rounded-lg border border-slate-800 p-5">
          <h2 className="text-sm uppercase tracking-wider text-slate-400 mb-4">
            Snapshots recentes
          </h2>
          {snapshots.length === 0 ? (
            <p className="text-sm text-slate-500">
              Nenhum snapshot capturado ainda. Use "Capturar Snapshot" acima.
            </p>
          ) : (
            <ul className="space-y-1.5 text-sm max-h-72 overflow-y-auto">
              {snapshots.map((s) => (
                <li key={s.id} className="flex items-center gap-3 text-slate-300">
                  <span className="px-2 py-0.5 text-xs rounded-full bg-slate-700 w-32 text-center">
                    {SNAPSHOT_LABELS[s.snapshot_type] || s.snapshot_type}
                  </span>
                  <span className="text-xs text-slate-500 font-mono">
                    {new Date(s.captured_at).toLocaleString("pt-BR")}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div className="bg-slate-900 rounded-lg border border-slate-800 p-5">
        <h2 className="text-sm uppercase tracking-wider text-slate-400 mb-4">
          Backtest runs anteriores
        </h2>
        {runs.length === 0 ? (
          <p className="text-sm text-slate-500">Nenhum run anterior</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {runs.map((r) => (
              <li
                key={r.id}
                className="flex items-center justify-between py-2 border-b border-slate-800/50"
              >
                <div>
                  <span className="font-medium">Run #{r.id}</span>
                  <span className="text-slate-500 ml-2 text-xs">
                    {new Date(r.created_at).toLocaleString("pt-BR")}
                  </span>
                </div>
                <div className="text-xs text-slate-400 flex gap-4">
                  <span>{r.config.days_back}d</span>
                  <span>{r.result.summary.tick_count} ticks</span>
                  <span className="text-emerald-400">
                    {r.result.summary.total_patterns_observed} patterns
                  </span>
                  <span className="text-amber-400">
                    {r.result.summary.total_chains_observed} chains
                  </span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

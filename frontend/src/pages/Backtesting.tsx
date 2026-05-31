import { useEffect, useState } from "react";
import {
  api, BacktestResult, BacktestRun, QualityMetrics, SystemSnapshot,
  UnlabelledEvent, UnlabelledResponse,
} from "../api";

type Labelable = {
  eventType: "pattern" | "chain";
  id: string;
  kind: string;
  title: string;
  detail: string;
  timestamp: string;
};

function toLabelable(e: UnlabelledEvent): Labelable {
  return {
    eventType: e.event_type === "chain" ? "chain" : "pattern",
    id: e.event_id,
    kind: e.kind,
    title: e.title,
    detail: e.detail,
    timestamp: e.timestamp,
  };
}

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
  const [labelQueue, setLabelQueue] = useState<Labelable[]>([]);
  const [labelIdx, setLabelIdx] = useState(0);
  const [labelledCount, setLabelledCount] = useState(0);
  const [labelMsg, setLabelMsg] = useState("");
  const [labelTotal, setLabelTotal] = useState(0);
  const [labelLoadingMore, setLabelLoadingMore] = useState(false);
  const [qualityBy, setQualityBy] = useState<"marked_at" | "event_timestamp">(
    "marked_at",
  );

  const loadAll = async () => {
    try {
      const [r, s, q] = await Promise.all([
        api.get("/backtest/runs", { params: { limit: 10 } }),
        api.get("/snapshots", { params: { days: 30, limit: 30 } }),
        api.get<QualityMetrics>("/metrics/quality", {
          params: { days: 90, by: qualityBy },
        }),
      ]);
      setRuns(r.data.runs || []);
      setSnapshots(s.data.snapshots || []);
      setQuality(q.data);
    } catch (e) {
      console.error(e);
    }
  };

  const loadLabelQueue = async () => {
    try {
      const res = await api.get<UnlabelledResponse>("/events/unlabelled", {
        params: { limit: 50, offset: 0 },
      });
      setLabelQueue((res.data.events || []).map(toLabelable));
      setLabelTotal(res.data.total || 0);
      setLabelIdx(0);
    } catch (e) {
      console.error(e);
    }
  };

  const loadMore = async () => {
    if (labelLoadingMore) return;
    setLabelLoadingMore(true);
    try {
      // offset = current queue length: every mark removes the item server-side
      // too, so the queue always holds a prefix of the unlabelled ordering.
      const res = await api.get<UnlabelledResponse>("/events/unlabelled", {
        params: { limit: 50, offset: labelQueue.length },
      });
      const have = new Set(labelQueue.map((it) => `${it.eventType}:${it.id}`));
      const fresh = (res.data.events || [])
        .map(toLabelable)
        .filter((it) => !have.has(`${it.eventType}:${it.id}`));
      setLabelQueue((q) => [...q, ...fresh]);
      setLabelTotal(res.data.total || 0);
    } catch (e) {
      console.error(e);
    } finally {
      setLabelLoadingMore(false);
    }
  };

  const refreshQuality = async () => {
    try {
      const q = await api.get<QualityMetrics>("/metrics/quality", {
        params: { days: 90, by: qualityBy },
      });
      setQuality(q.data);
    } catch (e) {
      console.error(e);
    }
  };

  const mark = async (outcome: "true_positive" | "false_positive" | "unclear") => {
    const item = labelQueue[labelIdx];
    if (!item) return;
    try {
      await api.post(`/outcomes/${item.eventType}/${item.id}`, {
        outcome,
        event_timestamp: item.timestamp,
      });
      const next = labelQueue.filter((_, i) => i !== labelIdx);
      setLabelQueue(next);
      setLabelIdx(Math.max(0, Math.min(labelIdx, next.length - 1)));
      setLabelledCount((n) => n + 1);
      setLabelTotal((n) => Math.max(0, n - 1));
      setLabelMsg("");
      refreshQuality();
    } catch (e: any) {
      const detail = e?.response?.data?.detail || e?.message || "erro desconhecido";
      setLabelMsg(`Erro ao marcar outcome: ${detail}`);
      console.error(e);
    }
  };

  useEffect(() => {
    loadAll();
    loadLabelQueue();
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) {
        return;
      }
      if (labelQueue.length === 0) return;
      const k = e.key.toLowerCase();
      if (k === "t") {
        e.preventDefault();
        mark("true_positive");
      } else if (k === "f") {
        e.preventDefault();
        mark("false_positive");
      } else if (k === "u") {
        e.preventDefault();
        mark("unclear");
      } else if (k === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setLabelIdx((i) => Math.min(i + 1, labelQueue.length - 1));
      } else if (k === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setLabelIdx((i) => Math.max(i - 1, 0));
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [labelQueue, labelIdx]);

  useEffect(() => {
    refreshQuality();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qualityBy]);

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
  const cur = labelQueue[labelIdx];

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

      <div className="bg-slate-900 rounded-lg border border-slate-800 p-5">
        <div className="flex items-center justify-between mb-1">
          <h2 className="text-sm uppercase tracking-wider text-slate-400">
            Rotular eventos (ground truth)
          </h2>
          <span className="text-xs text-slate-500">
            {labelTotal} por rotular · {labelledCount} marcados nesta sessão
          </span>
        </div>
        <p className="text-xs text-slate-500 mb-4">
          Atalhos: <kbd className="px-1 bg-slate-800 rounded">T</kbd> acertou (TP) ·{" "}
          <kbd className="px-1 bg-slate-800 rounded">F</kbd> falhou (FP) ·{" "}
          <kbd className="px-1 bg-slate-800 rounded">U</kbd> incerto ·{" "}
          <kbd className="px-1 bg-slate-800 rounded">J</kbd>/<kbd className="px-1 bg-slate-800 rounded">K</kbd> navegar
        </p>
        {labelMsg && <div className="text-sm text-red-400 mb-3">{labelMsg}</div>}
        {labelQueue.length === 0 || !cur ? (
          <p className="text-sm text-slate-500">
            Nada por rotular. Corre o backtest / aguarda novos patterns e chains.
          </p>
        ) : (
          <div className="space-y-4">
            <div className="bg-slate-950 border border-slate-700 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <span className="px-2 py-0.5 text-xs rounded-full bg-primary-600/30 text-primary-300">
                  {cur.kind}
                </span>
                <span className="text-sm font-medium">{cur.title}</span>
                <span className="ml-auto text-xs text-slate-500 font-mono">
                  {cur.timestamp ? new Date(cur.timestamp).toLocaleString("pt-BR") : "—"}
                </span>
              </div>
              {cur.detail && (
                <p className="text-sm text-slate-300 whitespace-pre-wrap mb-3 max-h-40 overflow-y-auto">
                  {cur.detail}
                </p>
              )}
              <div className="flex gap-2">
                <button
                  onClick={() => mark("true_positive")}
                  className="px-3 py-1.5 rounded text-sm font-medium bg-emerald-600/20 text-emerald-300 hover:bg-emerald-600/30 transition"
                >
                  [T] Acertou
                </button>
                <button
                  onClick={() => mark("false_positive")}
                  className="px-3 py-1.5 rounded text-sm font-medium bg-red-600/20 text-red-300 hover:bg-red-600/30 transition"
                >
                  [F] Falhou
                </button>
                <button
                  onClick={() => mark("unclear")}
                  className="px-3 py-1.5 rounded text-sm font-medium bg-slate-700 text-slate-300 hover:bg-slate-600 transition"
                >
                  [U] Incerto
                </button>
              </div>
            </div>

            {labelQueue.length > 1 && (
              <ul className="space-y-1 text-xs max-h-40 overflow-y-auto">
                {labelQueue.map((it, i) => (
                  <li key={`${it.eventType}:${it.id}`}>
                    <button
                      onClick={() => setLabelIdx(i)}
                      className={`w-full text-left px-2 py-1 rounded flex items-center gap-2 ${
                        i === labelIdx ? "bg-slate-800" : "hover:bg-slate-800/50"
                      }`}
                    >
                      <span className="text-slate-500 w-14">{it.kind}</span>
                      <span className="flex-1 truncate text-slate-300">{it.title}</span>
                      <span className="text-slate-600 font-mono">
                        {it.timestamp ? new Date(it.timestamp).toLocaleDateString("pt-BR") : ""}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}

            {labelQueue.length < labelTotal && (
              <button
                onClick={loadMore}
                disabled={labelLoadingMore}
                className="px-3 py-1.5 rounded text-sm font-medium bg-slate-800 hover:bg-slate-700 disabled:opacity-50 transition"
              >
                {labelLoadingMore ? "A carregar..." : "Carregar mais 50"}
              </button>
            )}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-5">
          <div className="flex items-center justify-between mb-4 gap-3">
            <h2 className="text-sm uppercase tracking-wider text-slate-400">
              Quality metrics ({quality?.window_days || 90}d)
            </h2>
            <select
              value={qualityBy}
              onChange={(e) =>
                setQualityBy(e.target.value as "marked_at" | "event_timestamp")
              }
              title="Coluna de tempo usada para a janela"
              className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-xs"
            >
              <option value="marked_at">Janela por marcação</option>
              <option value="event_timestamp">Janela por ocorrência</option>
            </select>
          </div>
          {quality && Object.keys(quality.by_type).length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                  <th className="py-2 text-left">Tipo</th>
                  <th className="py-2 text-right">TP</th>
                  <th className="py-2 text-right">FP</th>
                  <th className="py-2 text-right">n</th>
                  <th className="py-2 text-right">Precisao (95% CI)</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(quality.by_type).map(([type, m]) => {
                  const n = m.n ?? m.true_positive + m.false_positive;
                  const margin =
                    m.precision_low != null && m.precision_high != null
                      ? (m.precision_high - m.precision_low) / 2
                      : null;
                  return (
                    <tr key={type} className="border-b border-slate-800/50">
                      <td className="py-2 font-medium">{type}</td>
                      <td className="py-2 text-right text-emerald-400">{m.true_positive}</td>
                      <td className="py-2 text-right text-red-400">{m.false_positive}</td>
                      <td className="py-2 text-right text-slate-400">{n}</td>
                      <td className="py-2 text-right">
                        {m.precision != null ? (
                          <span>
                            {(m.precision * 100).toFixed(0)}%
                            {margin != null && (
                              <span className="text-slate-500 text-xs ml-1">
                                ±{Math.round(margin * 100)}%
                              </span>
                            )}
                          </span>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <p className="text-sm text-slate-500">
              Sem precisão ainda — use "Rotular eventos" acima para marcar TP/FP.
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

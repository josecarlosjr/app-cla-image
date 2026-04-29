import { useEffect, useState, useCallback } from "react";
import { api, Article, Pattern } from "../api";

const CATEGORIES = [
  "",
  "TECNOLOGIA_IA",
  "CIBERSEGURANCA",
  "CIENCIA",
  "ENERGIA",
  "MINERAIS_MINERACAO",
  "SUPPLY_CHAIN_LOGISTICA",
  "GEOPOLITICA_FINANCAS",
  "DEFESA_ESPACO",
  "DEVOPS_PLATFORM",
  "DADOS",
  "MERCADOS",
  "CIENCIA_ENERGIA",
];

const PATTERN_CATEGORIES = [
  "",
  "chips_ia",
  "energia",
  "minerais",
  "geopolitica",
  "ciberseguranca",
  "ciencia",
  "espaco_defesa",
  "financas",
  "cadeia_suprimentos",
];

const CONFIDENCE_LEVELS = ["", "ALTA", "MEDIA", "BAIXA"];

export default function News() {
  const [articles, setArticles] = useState<Article[]>([]);
  const [patterns, setPatterns] = useState<Pattern[]>([]);
  const [category, setCategory] = useState("");
  const [patternCategory, setPatternCategory] = useState("");
  const [patternConfidence, setPatternConfidence] = useState("");
  const [tab, setTab] = useState<"articles" | "patterns">("patterns");
  const [refreshing, setRefreshing] = useState(false);
  const [refreshResult, setRefreshResult] = useState("");
  const [detecting, setDetecting] = useState(false);
  const [detectResult, setDetectResult] = useState("");

  const loadData = useCallback(async () => {
    const patternParams: Record<string, string> = {};
    if (patternConfidence) patternParams.confidence = patternConfidence;
    if (patternCategory) patternParams.category = patternCategory;

    const [n, p] = await Promise.all([
      api.get<{ articles: Article[] }>("/news", {
        params: category ? { category } : {},
      }),
      api.get<{ patterns: Pattern[] }>("/patterns", {
        params: patternParams,
      }),
    ]);
    setArticles(n.data.articles || []);
    setPatterns((p.data.patterns || []).reverse());
  }, [category, patternCategory, patternConfidence]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleRefresh = async () => {
    setRefreshing(true);
    setRefreshResult("");
    try {
      const { data } = await api.post<{
        new_articles: number;
        total_cached: number;
        scored: number;
      }>("/feeds/refresh");
      setRefreshResult(
        `${data.new_articles} novos artigos, ${data.scored} com score`
      );
      await loadData();
    } catch {
      setRefreshResult("Erro ao atualizar feeds");
    } finally {
      setRefreshing(false);
    }
  };

  const handleDetect = async () => {
    setDetecting(true);
    setDetectResult("");
    try {
      const { data } = await api.post<{
        new_patterns: number;
        total_patterns: number;
        clusters: number;
        strong_clusters: number;
        articles: number;
        message?: string;
      }>("/patterns/detect");
      if (data.message) {
        setDetectResult(data.message);
      } else {
        setDetectResult(
          `${data.new_patterns} novos padroes (${data.strong_clusters} clusters fortes)`
        );
      }
      await loadData();
    } catch {
      setDetectResult("Erro ao detectar padroes");
    } finally {
      setDetecting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold">News & Patterns</h1>
          <p className="text-slate-400 mt-1">
            Feeds RSS + padroes detectados por correlacao multi-fonte
          </p>
        </div>
        <div className="flex flex-col items-end gap-2">
          <div className="flex items-center gap-2">
            {refreshResult && (
              <span className="text-xs text-slate-400">{refreshResult}</span>
            )}
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="px-4 py-2 bg-primary-500 hover:bg-primary-600 disabled:opacity-50 rounded-lg text-sm font-medium transition"
            >
              {refreshing ? "Atualizando..." : "Atualizar feeds"}
            </button>
          </div>
          <div className="flex items-center gap-2">
            {detectResult && (
              <span className="text-xs text-slate-400">{detectResult}</span>
            )}
            <button
              onClick={handleDetect}
              disabled={detecting || refreshing}
              className="px-4 py-2 bg-amber-600 hover:bg-amber-700 disabled:opacity-50 rounded-lg text-sm font-medium transition"
              title="Usa Claude API (~$0.04 por deteccao)"
            >
              {detecting ? "Detectando..." : "Detectar padroes (~$0.04)"}
            </button>
          </div>
        </div>
      </div>

      <div className="flex gap-2 border-b border-slate-800">
        <button
          onClick={() => setTab("patterns")}
          className={`px-4 py-2 ${
            tab === "patterns"
              ? "border-b-2 border-primary-500 text-white"
              : "text-slate-400"
          }`}
        >
          Patterns ({patterns.length})
        </button>
        <button
          onClick={() => setTab("articles")}
          className={`px-4 py-2 ${
            tab === "articles"
              ? "border-b-2 border-primary-500 text-white"
              : "text-slate-400"
          }`}
        >
          Artigos ({articles.length})
        </button>
      </div>

      {tab === "patterns" ? (
        <div className="space-y-3">
          <div className="flex gap-3">
            <select
              value={patternCategory}
              onChange={(e) => setPatternCategory(e.target.value)}
              className="bg-slate-800 rounded-lg px-3 py-2 text-sm"
            >
              {PATTERN_CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {c || "Todas as categorias"}
                </option>
              ))}
            </select>
            <select
              value={patternConfidence}
              onChange={(e) => setPatternConfidence(e.target.value)}
              className="bg-slate-800 rounded-lg px-3 py-2 text-sm"
            >
              {CONFIDENCE_LEVELS.map((c) => (
                <option key={c} value={c}>
                  {c
                    ? c === "ALTA"
                      ? "Forte"
                      : c === "MEDIA"
                      ? "Media"
                      : "Fraca"
                    : "Todas as confianças"}
                </option>
              ))}
            </select>
          </div>
          {patterns.map((p, i) => (
            <div
              key={i}
              className="bg-slate-900 rounded-lg p-5 border border-slate-800"
            >
              <div className="flex items-center gap-2 mb-3">
                <span
                  className={`px-2 py-1 rounded text-xs font-bold ${
                    p.confidence === "ALTA"
                      ? "bg-red-500/20 text-red-400"
                      : p.confidence === "MEDIA"
                      ? "bg-amber-500/20 text-amber-400"
                      : "bg-slate-500/20 text-slate-400"
                  }`}
                >
                  {p.confidence}
                </span>
                <span className="text-xs text-slate-500">
                  {p.num_sources} fontes
                </span>
                <div className="flex gap-1 ml-auto">
                  {p.categories.map((c) => (
                    <span
                      key={c}
                      className="text-xs bg-slate-800 px-2 py-0.5 rounded"
                    >
                      {c}
                    </span>
                  ))}
                </div>
              </div>
              <pre className="text-sm whitespace-pre-wrap text-slate-200">
                {p.analysis}
              </pre>
              {p.articles?.length > 0 && (
                <details className="mt-3">
                  <summary className="text-xs text-slate-400 cursor-pointer">
                    Fontes
                  </summary>
                  <ul className="mt-2 space-y-1 text-xs">
                    {p.articles.map((a, j) => (
                      <li key={j}>
                        <a
                          href={a.url}
                          target="_blank"
                          rel="noopener"
                          className="text-primary-500 hover:underline"
                        >
                          {a.source}: {a.title}
                        </a>
                      </li>
                    ))}
                  </ul>
                </details>
              )}
            </div>
          ))}
          {patterns.length === 0 && (
            <p className="text-slate-500">
              Nenhum padrao detectado. Clique em "Atualizar feeds" para buscar
              artigos — padroes surgem quando 2+ fontes cobrem o mesmo tema.
            </p>
          )}
        </div>
      ) : (
        <>
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="bg-slate-800 rounded-lg px-3 py-2"
          >
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c || "Todas as categorias"}
              </option>
            ))}
          </select>

          <div className="space-y-2">
            {articles.slice(0, 50).map((a, i) => (
              <a
                key={i}
                href={a.url}
                target="_blank"
                rel="noopener"
                className="block bg-slate-900 rounded-lg p-4 border border-slate-800 hover:border-primary-500 transition"
              >
                <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
                  <span>{a.source}</span>
                  <span>·</span>
                  <span className="text-primary-500">{a.category}</span>
                  {a.relevance_trusted && (
                    <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold">
                      premium
                    </span>
                  )}
                  {a.relevance_score != null && (
                    <span
                      className={`ml-auto px-1.5 py-0.5 rounded text-xs font-mono ${
                        a.relevance_score >= 70
                          ? "bg-green-500/20 text-green-400"
                          : a.relevance_score >= 45
                          ? "bg-amber-500/20 text-amber-400"
                          : "bg-slate-700 text-slate-400"
                      }`}
                    >
                      {a.relevance_score}
                    </span>
                  )}
                </div>
                <h3 className="font-medium text-slate-100">{a.title}</h3>
                <p className="text-sm text-slate-400 mt-1 line-clamp-2">
                  {a.summary}
                </p>
              </a>
            ))}
            {articles.length === 0 && (
              <p className="text-slate-500">
                Nenhum artigo ainda. Clique em "Atualizar feeds" para buscar
                artigos de 37+ fontes RSS.
              </p>
            )}
          </div>
        </>
      )}
    </div>
  );
}

import { useEffect, useState, useCallback, useMemo } from "react";
import { api, Article, Pattern } from "../api";

// ---------------------------------------------------------------------------
// Markdown rendering (kept from previous fix)
// ---------------------------------------------------------------------------
//
// Pattern analyses come from the LLM as a markdown-flavoured string.
// The prompt asks for `*HEADER:*` (Telegram-legacy single-asterisk
// convention) but Sonnet/Haiku regularly drift to standard CommonMark
// `**HEADER:**`. Render both as bold so the user sees consistent
// formatting regardless of which spelling the model chose.
//
// We HTML-escape the input first, then re-introduce only `<strong>`
// and `<code>` tags. dangerouslySetInnerHTML is safe here because the
// only HTML in the output is the small set we explicitly emit.
function renderMd(text: string): string {
  const escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  return escaped
    .replace(/\*\*([^\n*]+?)\*\*/g, "<strong>$1</strong>")
    .replace(/__([^\n_]+?)__/g, "<strong>$1</strong>")
    .replace(
      /(?<!\*)\*(?!\*)([^\n*]+?)(?<!\*)\*(?!\*)/g,
      "<strong>$1</strong>",
    )
    .replace(/`([^`\n]+?)`/g, "<code>$1</code>");
}

// ---------------------------------------------------------------------------
// Read tracking — localStorage-backed
// ---------------------------------------------------------------------------
//
// Single-user app so per-browser state is fine. Patterns are tracked by
// their numeric id; articles by their canonical URL (DB primary key).

const READ_PATTERNS_KEY = "pia:read-patterns";
const READ_ARTICLES_KEY = "pia:read-articles";

function loadReadSet(key: string): Set<string> {
  try {
    const raw = localStorage.getItem(key);
    return new Set<string>(raw ? JSON.parse(raw) : []);
  } catch {
    return new Set<string>();
  }
}

function saveReadSet(key: string, set: Set<string>): void {
  try {
    localStorage.setItem(key, JSON.stringify([...set]));
  } catch {
    // Quota exceeded or storage disabled — read state simply won't
    // persist between sessions; current-tab UI keeps working.
  }
}

// Parse an ISO timestamp into a compact PT-BR relative label
// ("agora", "há 2h", "há 3d", "12 mai") or "" when missing/invalid.
function formatRelativeTime(iso?: string | null): string {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "";
  const diffMin = Math.max(0, Math.floor((Date.now() - t) / 60_000));
  if (diffMin < 1) return "agora";
  if (diffMin < 60) return `há ${diffMin}min`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `há ${diffHr}h`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 7) return `há ${diffDay}d`;
  return new Date(iso).toLocaleDateString("pt-BR", {
    day: "2-digit",
    month: "short",
  });
}

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
  const [readPatterns, setReadPatterns] = useState<Set<string>>(() =>
    loadReadSet(READ_PATTERNS_KEY),
  );
  const [readArticles, setReadArticles] = useState<Set<string>>(() =>
    loadReadSet(READ_ARTICLES_KEY),
  );

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

  const togglePatternRead = (id: string) => {
    setReadPatterns((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      saveReadSet(READ_PATTERNS_KEY, next);
      return next;
    });
  };

  const toggleArticleRead = (url: string) => {
    setReadArticles((prev) => {
      const next = new Set(prev);
      if (next.has(url)) next.delete(url);
      else next.add(url);
      saveReadSet(READ_ARTICLES_KEY, next);
      return next;
    });
  };

  const markArticleRead = (url: string) => {
    setReadArticles((prev) => {
      if (prev.has(url)) return prev;
      const next = new Set(prev);
      next.add(url);
      saveReadSet(READ_ARTICLES_KEY, next);
      return next;
    });
  };

  // Sort: unread first (preserve original order), read at the end.
  // Memoised so the sort only re-runs when the data or read-set changes.
  const sortedPatterns = useMemo(() => {
    const unread: Pattern[] = [];
    const read: Pattern[] = [];
    for (const p of patterns) {
      if (readPatterns.has(String(p.id))) read.push(p);
      else unread.push(p);
    }
    return { unread, read, all: [...unread, ...read] };
  }, [patterns, readPatterns]);

  const sortedArticles = useMemo(() => {
    const visible = articles.slice(0, 50);
    const unread: Article[] = [];
    const read: Article[] = [];
    for (const a of visible) {
      if (readArticles.has(a.url)) read.push(a);
      else unread.push(a);
    }
    return { unread, read, all: [...unread, ...read] };
  }, [articles, readArticles]);

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
          Patterns ({sortedPatterns.unread.length}
          {sortedPatterns.read.length > 0 && (
            <span className="text-slate-500"> / {patterns.length}</span>
          )}
          )
        </button>
        <button
          onClick={() => setTab("articles")}
          className={`px-4 py-2 ${
            tab === "articles"
              ? "border-b-2 border-primary-500 text-white"
              : "text-slate-400"
          }`}
        >
          Artigos ({sortedArticles.unread.length}
          {sortedArticles.read.length > 0 && (
            <span className="text-slate-500"> / {sortedArticles.all.length}</span>
          )}
          )
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
          {sortedPatterns.all.map((p) => {
            const id = String(p.id);
            const isRead = readPatterns.has(id);
            return (
              <div
                key={id}
                className={`rounded-lg p-5 border transition-opacity ${
                  isRead
                    ? "bg-slate-900/40 border-slate-800/40 opacity-50 hover:opacity-75"
                    : "bg-slate-900 border-slate-800"
                }`}
              >
                <div className="flex items-center gap-2 mb-3 flex-wrap">
                  <span
                    className={`px-2 py-1 rounded text-xs font-bold ${
                      isRead
                        ? "bg-slate-700/40 text-slate-500"
                        : p.confidence === "ALTA"
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
                  {p.timestamp && (
                    <span
                      className="text-xs text-slate-500"
                      title={new Date(p.timestamp).toLocaleString("pt-BR")}
                    >
                      · {formatRelativeTime(p.timestamp)}
                    </span>
                  )}
                  <div className="flex gap-1 ml-auto items-center">
                    {p.categories.map((c) => (
                      <span
                        key={c}
                        className="text-xs bg-slate-800 px-2 py-0.5 rounded"
                      >
                        {c}
                      </span>
                    ))}
                    <button
                      onClick={() => togglePatternRead(id)}
                      className={`text-xs px-2 py-0.5 rounded transition ${
                        isRead
                          ? "bg-slate-800 text-slate-500 hover:bg-slate-700 hover:text-slate-300"
                          : "bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                      }`}
                      title={
                        isRead
                          ? "Clique para desmarcar"
                          : "Clique para marcar como lido"
                      }
                    >
                      {isRead ? "✓ lido" : "marcar lido"}
                    </button>
                  </div>
                </div>
                <div
                  className="text-sm text-slate-200 whitespace-pre-line leading-relaxed [&_strong]:text-white [&_strong]:font-semibold [&_code]:bg-slate-800 [&_code]:px-1.5 [&_code]:py-0.5 [&_code]:rounded [&_code]:text-xs"
                  dangerouslySetInnerHTML={{ __html: renderMd(p.analysis) }}
                />
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
            );
          })}
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
            {sortedArticles.all.map((a) => {
              const isRead = readArticles.has(a.url);
              return (
                <div
                  key={a.url}
                  className={`relative rounded-lg p-4 border transition-opacity ${
                    isRead
                      ? "bg-slate-900/40 border-slate-800/40 opacity-50 hover:opacity-75"
                      : "bg-slate-900 border-slate-800 hover:border-primary-500"
                  }`}
                >
                  <a
                    href={a.url}
                    target="_blank"
                    rel="noopener"
                    onClick={() => markArticleRead(a.url)}
                    className="block"
                  >
                    <div className="flex items-center gap-2 text-xs text-slate-400 mb-1 flex-wrap">
                      <span>{a.source}</span>
                      <span>·</span>
                      <span className="text-primary-500">{a.category}</span>
                      {a.fetched_at && (
                        <>
                          <span>·</span>
                          <span
                            className="text-slate-500"
                            title={new Date(a.fetched_at).toLocaleString("pt-BR")}
                          >
                            {formatRelativeTime(a.fetched_at)}
                          </span>
                        </>
                      )}
                      {a.relevance_trusted && (
                        <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold">
                          premium
                        </span>
                      )}
                      {a.relevance_score != null && (
                        <span
                          className={`ml-auto px-1.5 py-0.5 rounded text-xs font-mono ${
                            isRead
                              ? "bg-slate-700/40 text-slate-500"
                              : a.relevance_score >= 70
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
                    <h3
                      className={`font-medium ${
                        isRead ? "text-slate-400" : "text-slate-100"
                      }`}
                    >
                      {a.title}
                    </h3>
                    <p className="text-sm text-slate-400 mt-1 line-clamp-2">
                      {a.summary}
                    </p>
                  </a>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      e.preventDefault();
                      toggleArticleRead(a.url);
                    }}
                    className={`absolute top-2 right-2 text-xs px-2 py-0.5 rounded transition ${
                      isRead
                        ? "bg-slate-800 text-slate-500 hover:bg-slate-700 hover:text-slate-300"
                        : "bg-slate-800/60 text-slate-400 hover:bg-emerald-500/20 hover:text-emerald-400"
                    }`}
                    title={isRead ? "Marcar como nao lido" : "Marcar como lido"}
                  >
                    {isRead ? "✓ lido" : "marcar lido"}
                  </button>
                </div>
              );
            })}
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

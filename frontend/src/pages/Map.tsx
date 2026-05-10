import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape, { Core } from "cytoscape";
import { api, MapNode, MapConnection, Pattern } from "../api";

// ---------------------------------------------------------------------------
// Static maps
// ---------------------------------------------------------------------------

const CATEGORY_LABELS: Record<string, string> = {
  chips_ia: "Chips & IA",
  energia: "Energia",
  minerais: "Minerais",
  geopolitica: "Geopolitica",
  ciberseguranca: "Ciberseguranca",
  ciencia: "Ciencia",
  espaco_defesa: "Espaco & Defesa",
  financas: "Financas",
  cadeia_suprimentos: "Cadeia de Suprimentos",
};

const TREND_LABEL: Record<string, string> = {
  rising: "subindo",
  falling: "caindo",
  stable: "estavel",
};

const TREND_ICON: Record<string, string> = {
  rising: "↑",
  falling: "↓",
  stable: "→",
};

const TREND_CLASS: Record<string, string> = {
  rising: "text-red-400 bg-red-500/10",
  falling: "text-blue-400 bg-blue-500/10",
  stable: "text-slate-400 bg-slate-500/10",
};

// Score → cycle of intensity colours (matches the node fill on the graph)
function scoreColour(score: number): string {
  if (score >= 75) return "#ef4444";
  if (score >= 50) return "#f59e0b";
  if (score >= 25) return "#3b82f6";
  return "#475569";
}

function scoreClass(score: number): string {
  if (score >= 75) return "bg-red-500/20 text-red-400";
  if (score >= 50) return "bg-amber-500/20 text-amber-400";
  if (score >= 25) return "bg-blue-500/20 text-blue-400";
  return "bg-slate-500/20 text-slate-400";
}

// Compact PT-BR relative date — shared shape with News.tsx
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

// Strip markdown decoration so the panel preview reads as plain text.
// Full formatting is on the News page; here we just want a tidy excerpt.
function stripMd(text: string): string {
  return text
    .replace(/\*\*([^\n*]+?)\*\*/g, "$1")
    .replace(/__([^\n_]+?)__/g, "$1")
    .replace(/\*([^\n*]+?)\*/g, "$1")
    .replace(/`([^`\n]+?)`/g, "$1")
    .replace(/\s+/g, " ")
    .trim();
}

// ---------------------------------------------------------------------------
// Selection model
// ---------------------------------------------------------------------------

type SelectedNode = {
  kind: "node";
  id: string;
  label: string;
  score: number;
  trend: string;
  articles: number;
};

type SelectedEdge = {
  kind: "edge";
  source: string;
  target: string;
  score: number;
  pattern: string;
};

type Selection = SelectedNode | SelectedEdge | null;

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function MapPage() {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [selected, setSelected] = useState<Selection>(null);
  const [patterns, setPatterns] = useState<Pattern[]>([]);
  const [loadingPatterns, setLoadingPatterns] = useState(false);

  // -------------------------------------------------------------------
  // Cytoscape setup
  // -------------------------------------------------------------------
  useEffect(() => {
    let cancelled = false;

    (async () => {
      const { data } = await api.get<{
        nodes: MapNode[];
        connections: MapConnection[];
      }>("/map/nodes");

      if (cancelled || !containerRef.current) return;

      const elements = [
        ...data.nodes.map((n) => ({
          data: {
            id: n.id,
            label: CATEGORY_LABELS[n.id] || n.id,
            score: n.score,
            trend: n.trend,
            articles: n.articles,
          },
        })),
        ...data.connections.map((c, i) => ({
          data: {
            id: `e${i}`,
            source: c.from,
            target: c.to,
            score: c.score,
            pattern: c.pattern,
          },
        })),
      ];

      const cy = cytoscape({
        container: containerRef.current,
        elements,
        style: [
          {
            selector: "node",
            style: {
              "background-color": (ele: any) => scoreColour(ele.data("score")),
              label: "data(label)",
              color: "#fff",
              "text-valign": "center",
              "text-halign": "center",
              "font-size": 11,
              "text-wrap": "wrap",
              "text-max-width": "80px",
              width: (ele: any) => 40 + (ele.data("score") || 0) * 0.8,
              height: (ele: any) => 40 + (ele.data("score") || 0) * 0.8,
              "border-width": 2,
              "border-color": "#0f172a",
              "transition-property": "border-color border-width",
              "transition-duration": 150,
            } as any,
          },
          {
            selector: "edge",
            style: {
              width: (ele: any) => 1 + (ele.data("score") || 0) / 20,
              "line-color": "#64748b",
              "target-arrow-color": "#64748b",
              "curve-style": "bezier",
              opacity: 0.6,
            } as any,
          },
          {
            selector: "node:selected",
            style: {
              "border-color": "#3b82f6",
              "border-width": 4,
            },
          },
          {
            selector: "edge:selected",
            style: {
              "line-color": "#3b82f6",
              opacity: 1,
            },
          },
        ],
        layout: {
          name: "cose",
          animate: true,
          idealEdgeLength: 120,
          nodeOverlap: 20,
          padding: 40,
        } as any,
      });

      cy.on("tap", "node", (evt) => {
        const d = evt.target.data();
        setSelected({
          kind: "node",
          id: d.id,
          label: d.label,
          score: d.score,
          trend: d.trend,
          articles: d.articles,
        });
      });
      cy.on("tap", "edge", (evt) => {
        const d = evt.target.data();
        setSelected({
          kind: "edge",
          source: d.source,
          target: d.target,
          score: d.score,
          pattern: d.pattern,
        });
      });
      // Click on background → clear
      cy.on("tap", (evt) => {
        if (evt.target === cy) setSelected(null);
      });

      cyRef.current = cy;
    })();

    return () => {
      cancelled = true;
      cyRef.current?.destroy();
    };
  }, []);

  // -------------------------------------------------------------------
  // Fetch patterns for the selected node's category
  // -------------------------------------------------------------------
  useEffect(() => {
    if (!selected || selected.kind !== "node") {
      setPatterns([]);
      return;
    }
    let cancelled = false;
    setLoadingPatterns(true);
    api
      .get<{ patterns: Pattern[] }>("/patterns", {
        params: { category: selected.id },
      })
      .then(({ data }) => {
        if (!cancelled) {
          setPatterns(data.patterns || []);
          setLoadingPatterns(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setPatterns([]);
          setLoadingPatterns(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  // Stable React key so the panel remounts on every new selection,
  // re-triggering the fade-in keyframe.
  const panelKey = useMemo(() => {
    if (!selected) return "empty";
    if (selected.kind === "node") return `node-${selected.id}`;
    return `edge-${selected.source}-${selected.target}`;
  }, [selected]);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-3xl font-bold">Mapa de dependencias</h1>
        <p className="text-slate-400 mt-1">
          Intensidade por categoria (tamanho e cor) + conexoes detectadas por
          padroes. Clique numa esfera para ver os padroes recentes daquela
          area.
        </p>
      </div>

      <div className="flex gap-4">
        <div
          ref={containerRef}
          className="flex-1 bg-slate-900 rounded-lg border border-slate-800"
          style={{ height: 600 }}
        />
        <aside className="w-80 bg-slate-900 rounded-lg border border-slate-800 flex flex-col"
               style={{ height: 600 }}>
          <div
            key={panelKey}
            className="flex-1 overflow-y-auto p-5 map-panel-fade"
          >
            {!selected && (
              <div className="text-slate-500 text-sm h-full flex items-center justify-center text-center">
                Clique numa esfera para ver os padroes recentes,
                <br />ou numa conexao para ver o que conecta as duas areas.
              </div>
            )}

            {selected?.kind === "node" && (
              <NodeDetail
                node={selected}
                patterns={patterns}
                loading={loadingPatterns}
              />
            )}

            {selected?.kind === "edge" && (
              <EdgeDetail edge={selected} />
            )}
          </div>
        </aside>
      </div>

      {/* Self-contained keyframe — avoids touching tailwind.config */}
      <style>{`
        .map-panel-fade {
          animation: mapPanelFadeIn 220ms ease-out;
        }
        @keyframes mapPanelFadeIn {
          from { opacity: 0; transform: translateY(8px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function NodeDetail({
  node,
  patterns,
  loading,
}: {
  node: SelectedNode;
  patterns: Pattern[];
  loading: boolean;
}) {
  return (
    <div className="space-y-4">
      <header>
        <h3 className="text-lg font-bold text-white">{node.label}</h3>
        <div className="flex flex-wrap gap-2 mt-2 text-xs">
          <span
            className={`px-2 py-1 rounded font-mono ${scoreClass(node.score)}`}
            title="Score de intensidade (0-100)"
          >
            score {node.score}
          </span>
          <span
            className={`px-2 py-1 rounded ${TREND_CLASS[node.trend] || TREND_CLASS.stable}`}
          >
            {TREND_ICON[node.trend] || "→"} {TREND_LABEL[node.trend] || node.trend}
          </span>
          <span className="px-2 py-1 rounded bg-slate-800 text-slate-300">
            {node.articles} {node.articles === 1 ? "artigo" : "artigos"}
          </span>
        </div>
      </header>

      <section>
        <h4 className="text-xs uppercase tracking-wider text-slate-500 mb-2">
          Padroes recentes
        </h4>
        {loading && (
          <div className="space-y-2">
            <div className="h-16 bg-slate-800/50 rounded animate-pulse" />
            <div className="h-16 bg-slate-800/50 rounded animate-pulse" />
          </div>
        )}
        {!loading && patterns.length === 0 && (
          <p className="text-sm text-slate-500">
            Nenhum padrao detectado nesta categoria. Va para News & Patterns
            e clique em "Detectar padroes" se ha artigos novos.
          </p>
        )}
        {!loading && patterns.length > 0 && (
          <ul className="space-y-3">
            {patterns.slice(0, 6).map((p) => (
              <PatternRow key={p.id} pattern={p} />
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function PatternRow({ pattern }: { pattern: Pattern }) {
  const preview = stripMd(pattern.analysis).slice(0, 180);
  const confColour =
    pattern.confidence === "ALTA"
      ? "bg-red-500/20 text-red-400"
      : pattern.confidence === "MEDIA"
      ? "bg-amber-500/20 text-amber-400"
      : "bg-slate-500/20 text-slate-400";

  return (
    <li className="bg-slate-950/40 rounded-lg p-3 border border-slate-800/60">
      <div className="flex items-center gap-2 text-xs mb-1">
        <span className={`px-2 py-0.5 rounded font-bold ${confColour}`}>
          {pattern.confidence}
        </span>
        <span className="text-slate-500">{pattern.num_sources} fontes</span>
        {pattern.timestamp && (
          <span
            className="text-slate-500 ml-auto"
            title={new Date(pattern.timestamp).toLocaleString("pt-BR")}
          >
            {formatRelativeTime(pattern.timestamp)}
          </span>
        )}
      </div>
      <p className="text-xs text-slate-300 leading-relaxed line-clamp-3">
        {preview}
        {pattern.analysis.length > preview.length && "…"}
      </p>
      {pattern.articles?.length > 0 && (
        <details className="mt-2">
          <summary className="text-xs text-slate-500 cursor-pointer hover:text-slate-300">
            Fontes ({pattern.articles.length})
          </summary>
          <ul className="mt-1 space-y-1 text-xs pl-2">
            {pattern.articles.slice(0, 5).map((a, j) => (
              <li key={j} className="truncate">
                <a
                  href={a.url}
                  target="_blank"
                  rel="noopener"
                  className="text-primary-500 hover:underline"
                  title={a.title}
                >
                  {a.source}: {a.title}
                </a>
              </li>
            ))}
          </ul>
        </details>
      )}
    </li>
  );
}

function EdgeDetail({ edge }: { edge: SelectedEdge }) {
  const fromLabel = CATEGORY_LABELS[edge.source] || edge.source;
  const toLabel = CATEGORY_LABELS[edge.target] || edge.target;
  return (
    <div className="space-y-3">
      <header>
        <h3 className="text-lg font-bold text-white">
          {fromLabel} <span className="text-slate-500">↔</span> {toLabel}
        </h3>
        <div className="mt-2 text-xs">
          <span
            className={`px-2 py-1 rounded font-mono ${scoreClass(edge.score)}`}
          >
            score {edge.score}
          </span>
        </div>
      </header>
      {edge.pattern && (
        <div>
          <h4 className="text-xs uppercase tracking-wider text-slate-500 mb-1">
            Padrao que conecta as duas areas
          </h4>
          <p className="text-sm text-slate-300 leading-relaxed">
            {stripMd(edge.pattern)}
          </p>
        </div>
      )}
    </div>
  );
}

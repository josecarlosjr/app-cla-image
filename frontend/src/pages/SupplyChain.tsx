import { useEffect, useRef, useState, useCallback } from "react";
import cytoscape, { Core } from "cytoscape";
import {
  api,
  SupplyChainGraph,
  SupplyChainNode,
  SupplyChainAnalysis,
  SupplyChainImpact,
} from "../api";

const TYPE_COLORS: Record<string, string> = {
  mineral: "#f59e0b",
  component: "#3b82f6",
  product: "#10b981",
  infra: "#8b5cf6",
};

const TYPE_LABELS: Record<string, string> = {
  mineral: "Mineral",
  component: "Componente",
  product: "Produto",
  infra: "Infraestrutura",
};

const SENTIMENT_COLORS: Record<string, string> = {
  shortage: "#ef4444",
  disruption: "#ef4444",
  price_up: "#f97316",
  neutral: "#64748b",
  price_down: "#22c55e",
  surplus: "#22c55e",
  expansion: "#3b82f6",
};

function heatColor(mentions: number): string {
  if (mentions >= 20) return "#ef4444";
  if (mentions >= 10) return "#f59e0b";
  if (mentions >= 3) return "#3b82f6";
  return "#334155";
}

function nodeSize(node: SupplyChainNode): number {
  const base = node.type === "product" ? 55 : node.type === "infra" ? 50 : node.type === "component" ? 45 : 40;
  return base + Math.min(node.mentions_7d * 2, 30);
}

type SelectedInfo = {
  node?: SupplyChainNode;
  impact?: SupplyChainImpact;
};

export default function SupplyChain() {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [graph, setGraph] = useState<SupplyChainGraph | null>(null);
  const [analysis, setAnalysis] = useState<SupplyChainAnalysis | null>(null);
  const [selected, setSelected] = useState<SelectedInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [showAlerts, setShowAlerts] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [graphRes, analysisRes] = await Promise.all([
          api.get<SupplyChainGraph>("/supply-chain"),
          api.get<SupplyChainAnalysis>("/supply-chain/analysis"),
        ]);
        if (cancelled) return;
        setGraph(graphRes.data);
        setAnalysis(analysisRes.data);
      } catch (err) {
        console.error("Failed to load supply chain data:", err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!graph || !containerRef.current) return;

    const spikeNodes = new Set(
      analysis?.spikes.map((s) => s.node_id) ?? []
    );

    const elements = [
      ...graph.nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.name,
          nodeType: n.type,
          mentions: n.mentions_7d,
          bg: TYPE_COLORS[n.type] || "#475569",
          size: nodeSize(n),
          borderColor: spikeNodes.has(n.id) ? "#ef4444" : "#0f172a",
          borderWidth: spikeNodes.has(n.id) ? 4 : 2,
        },
      })),
      ...graph.edges.map((e, i) => ({
        data: {
          id: `e${i}`,
          source: e.src,
          target: e.dst,
          relation: e.relation,
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
            "background-color": "data(bg)",
            label: "data(label)",
            color: "#fff",
            "text-valign": "bottom",
            "text-margin-y": 6,
            "font-size": 10,
            "text-wrap": "wrap",
            "text-max-width": "90px",
            width: "data(size)",
            height: "data(size)",
            "border-width": "data(borderWidth)",
            "border-color": "data(borderColor)",
            "text-outline-width": 2,
            "text-outline-color": "#0f172a",
          } as any,
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#475569",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#475569",
            "curve-style": "bezier",
            opacity: 0.5,
            "arrow-scale": 0.8,
          } as any,
        },
        {
          selector: "node:selected",
          style: { "border-color": "#38bdf8", "border-width": 5 },
        },
        {
          selector: ".highlighted",
          style: {
            "border-color": "#f59e0b",
            "border-width": 4,
            opacity: 1,
          },
        },
        {
          selector: ".dimmed",
          style: { opacity: 0.15 },
        },
        {
          selector: "edge.highlighted",
          style: {
            "line-color": "#f59e0b",
            "target-arrow-color": "#f59e0b",
            width: 3,
            opacity: 1,
          } as any,
        },
      ],
      layout: {
        name: "breadthfirst",
        directed: true,
        spacingFactor: 1.3,
        padding: 40,
        roots: graph.nodes
          .filter((n) => n.type === "product" || n.type === "infra")
          .map((n) => n.id),
      } as any,
    });

    cy.on("tap", "node", async (evt) => {
      const id = evt.target.data("id");
      const node = graph.nodes.find((n) => n.id === id);
      if (!node) return;

      cy.elements().removeClass("highlighted dimmed");
      cy.elements().addClass("dimmed");
      evt.target.removeClass("dimmed").addClass("highlighted");
      evt.target.connectedEdges().removeClass("dimmed").addClass("highlighted");
      evt.target
        .connectedEdges()
        .connectedNodes()
        .removeClass("dimmed")
        .addClass("highlighted");

      setSelected({ node });

      try {
        const { data } = await api.get<SupplyChainImpact>(
          `/supply-chain/impact/${id}`
        );
        setSelected({ node, impact: data });
      } catch {
        // keep node info without impact
      }
    });

    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        cy.elements().removeClass("highlighted dimmed");
        setSelected(null);
      }
    });

    cyRef.current = cy;
    return () => { cy.destroy(); };
  }, [graph, analysis]);

  const handleExtract = useCallback(async () => {
    try {
      await api.post("/supply-chain/extract");
      window.location.reload();
    } catch (err) {
      console.error("Extract failed:", err);
    }
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-slate-400 text-lg">Carregando grafo de suprimentos...</div>
      </div>
    );
  }

  if (!graph) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-red-400 text-lg">Erro ao carregar dados da cadeia de suprimentos.</div>
      </div>
    );
  }

  const totalMentions = graph.nodes.reduce((s, n) => s + n.mentions_7d, 0);
  const spikeCount = analysis?.spikes.length ?? 0;
  const alertCount = analysis?.alerts.length ?? 0;

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold">Cadeia de Suprimentos</h1>
          <p className="text-slate-400 mt-1">
            Grafo de dependencias: minerais → componentes → produtos/infraestrutura
          </p>
        </div>
        <button
          onClick={handleExtract}
          className="px-4 py-2 text-sm bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition"
        >
          Extrair mencoes
        </button>
      </div>

      <div className="grid grid-cols-4 gap-3">
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-4">
          <div className="text-2xl font-bold">{graph.nodes.length}</div>
          <div className="text-xs text-slate-400">Nos no grafo</div>
        </div>
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-4">
          <div className="text-2xl font-bold">{graph.edges.length}</div>
          <div className="text-xs text-slate-400">Dependencias</div>
        </div>
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-4">
          <div className="text-2xl font-bold">{totalMentions}</div>
          <div className="text-xs text-slate-400">Mencoes (7d)</div>
        </div>
        <div
          className={`bg-slate-900 rounded-lg border p-4 cursor-pointer transition ${
            alertCount > 0
              ? "border-red-800 hover:border-red-600"
              : "border-slate-800"
          }`}
          onClick={() => setShowAlerts(!showAlerts)}
        >
          <div className={`text-2xl font-bold ${alertCount > 0 ? "text-red-400" : ""}`}>
            {spikeCount} spikes / {alertCount} alertas
          </div>
          <div className="text-xs text-slate-400">Clique para {showAlerts ? "fechar" : "ver"} alertas</div>
        </div>
      </div>

      {showAlerts && analysis && analysis.alerts.length > 0 && (
        <div className="bg-slate-900 rounded-lg border border-red-900/50 p-4 space-y-3 max-h-60 overflow-y-auto">
          {analysis.alerts.map((alert, i) => (
            <div key={i} className="text-sm text-slate-300 border-b border-slate-800 pb-2 last:border-0">
              {alert.text}
            </div>
          ))}
        </div>
      )}

      <div className="flex gap-4">
        <div className="flex-1 relative">
          <div
            ref={containerRef}
            className="bg-slate-900 rounded-lg border border-slate-800"
            style={{ height: 560 }}
          />
          <div className="absolute bottom-3 left-3 flex gap-3 text-xs">
            {Object.entries(TYPE_LABELS).map(([type, label]) => (
              <div key={type} className="flex items-center gap-1.5">
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: TYPE_COLORS[type] }}
                />
                <span className="text-slate-400">{label}</span>
              </div>
            ))}
          </div>
        </div>

        <aside className="w-80 bg-slate-900 rounded-lg border border-slate-800 p-5 overflow-y-auto" style={{ maxHeight: 560 }}>
          {selected?.node ? (
            <div className="space-y-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: TYPE_COLORS[selected.node.type] }}
                  />
                  <span className="text-xs text-slate-400 uppercase">
                    {TYPE_LABELS[selected.node.type]}
                  </span>
                </div>
                <h3 className="font-bold text-lg">{selected.node.name}</h3>
              </div>

              <div>
                <div className="text-xs text-slate-400 mb-1">Mencoes (7 dias)</div>
                <div className="flex items-center gap-2">
                  <div
                    className="h-2 rounded-full"
                    style={{
                      width: `${Math.min(selected.node.mentions_7d * 4, 100)}%`,
                      backgroundColor: heatColor(selected.node.mentions_7d),
                      minWidth: selected.node.mentions_7d > 0 ? 8 : 0,
                    }}
                  />
                  <span className="text-sm font-mono">{selected.node.mentions_7d}</span>
                </div>
              </div>

              {Object.keys(selected.node.sentiments).length > 0 && (
                <div>
                  <div className="text-xs text-slate-400 mb-2">Sinais detectados</div>
                  <div className="space-y-1">
                    {Object.entries(selected.node.sentiments)
                      .sort(([, a], [, b]) => b - a)
                      .map(([sentiment, count]) => (
                        <div key={sentiment} className="flex items-center justify-between text-sm">
                          <div className="flex items-center gap-2">
                            <div
                              className="w-2 h-2 rounded-full"
                              style={{ backgroundColor: SENTIMENT_COLORS[sentiment] || "#64748b" }}
                            />
                            <span className="text-slate-300">{sentiment}</span>
                          </div>
                          <span className="font-mono text-slate-400">{count}</span>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {selected.impact && (
                <>
                  {selected.impact.dependencies.length > 0 && (
                    <div>
                      <div className="text-xs text-slate-400 mb-1">
                        Depende de ({selected.impact.dependencies.length})
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {selected.impact.dependencies.map((dep) => {
                          const depNode = graph?.nodes.find((n) => n.id === dep);
                          return (
                            <span
                              key={dep}
                              className="px-2 py-0.5 text-xs rounded-full border"
                              style={{
                                borderColor: TYPE_COLORS[depNode?.type ?? ""] || "#475569",
                                color: TYPE_COLORS[depNode?.type ?? ""] || "#94a3b8",
                              }}
                            >
                              {depNode?.name || dep}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {selected.impact.dependents.length > 0 && (
                    <div>
                      <div className="text-xs text-slate-400 mb-1">
                        Usado por ({selected.impact.dependents.length})
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {selected.impact.dependents.map((dep) => {
                          const depNode = graph?.nodes.find((n) => n.id === dep);
                          return (
                            <span
                              key={dep}
                              className="px-2 py-0.5 text-xs rounded-full border"
                              style={{
                                borderColor: TYPE_COLORS[depNode?.type ?? ""] || "#475569",
                                color: TYPE_COLORS[depNode?.type ?? ""] || "#94a3b8",
                              }}
                            >
                              {depNode?.name || dep}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {selected.impact.impact_chain.length > 0 && (
                    <div>
                      <div className="text-xs text-slate-400 mb-2">Cadeia de impacto</div>
                      <div className="space-y-1">
                        {selected.impact.impact_chain.map((step, i) => {
                          const fromNode = graph?.nodes.find((n) => n.id === step.from);
                          const toNode = graph?.nodes.find((n) => n.id === step.to);
                          return (
                            <div key={i} className="text-xs text-slate-300 flex items-center gap-1">
                              <span style={{ paddingLeft: (step.depth - 1) * 12 }}>
                                {"→ "}
                              </span>
                              <span style={{ color: TYPE_COLORS[fromNode?.type ?? ""] }}>
                                {fromNode?.name || step.from}
                              </span>
                              <span className="text-slate-500">→</span>
                              <span style={{ color: TYPE_COLORS[toNode?.type ?? ""] }}>
                                {toNode?.name || step.to}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </>
              )}

              {analysis?.spikes.find((s) => s.node_id === selected.node?.id) && (
                <div className="bg-red-950/30 rounded-lg p-3 border border-red-900/50">
                  <div className="text-xs text-red-400 font-bold mb-1">SPIKE DETECTADO</div>
                  {(() => {
                    const spike = analysis?.spikes.find(
                      (s) => s.node_id === selected.node?.id
                    );
                    if (!spike) return null;
                    return (
                      <div className="text-sm text-slate-300">
                        {spike.total_24h} mencoes em 24h ({spike.ratio}x a media)
                        <br />
                        <span className={
                          spike.dominant_signal === "negative"
                            ? "text-red-400"
                            : spike.dominant_signal === "positive"
                            ? "text-green-400"
                            : "text-slate-400"
                        }>
                          Sinal dominante: {spike.dominant_signal}
                        </span>
                      </div>
                    );
                  })()}
                </div>
              )}
            </div>
          ) : (
            <div className="text-slate-500 text-sm">
              Clique em um no do grafo para ver detalhes — dependencias, mencoes recentes,
              sinais detectados e cadeia de impacto.
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

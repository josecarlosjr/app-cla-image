import { useEffect, useRef, useState } from "react";
import cytoscape, { Core } from "cytoscape";
import { api, MapNode, MapConnection } from "../api";

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

function scoreColour(score: number): string {
  if (score >= 75) return "#ef4444";
  if (score >= 50) return "#f59e0b";
  if (score >= 25) return "#3b82f6";
  return "#475569";
}

export default function MapPage() {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [selected, setSelected] = useState<{ id: string; info?: any } | null>(
    null
  );

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
        setSelected({ id: d.id, info: d });
      });
      cy.on("tap", "edge", (evt) => {
        const d = evt.target.data();
        setSelected({
          id: `${d.source} <-> ${d.target}`,
          info: { pattern: d.pattern, score: d.score },
        });
      });

      cyRef.current = cy;
    })();

    return () => {
      cancelled = true;
      cyRef.current?.destroy();
    };
  }, []);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-3xl font-bold">Mapa de dependencias</h1>
        <p className="text-slate-400 mt-1">
          Intensidade por categoria (tamanho e cor) + conexoes detectadas por
          padroes
        </p>
      </div>

      <div className="flex gap-4">
        <div
          ref={containerRef}
          className="flex-1 bg-slate-900 rounded-lg border border-slate-800"
          style={{ height: 600 }}
        />
        <aside className="w-80 bg-slate-900 rounded-lg border border-slate-800 p-5">
          {selected ? (
            <>
              <h3 className="font-bold text-lg mb-2">
                {CATEGORY_LABELS[selected.id] || selected.id}
              </h3>
              <pre className="text-xs text-slate-300 whitespace-pre-wrap">
                {JSON.stringify(selected.info, null, 2)}
              </pre>
            </>
          ) : (
            <div className="text-slate-500 text-sm">
              Clique em um no ou conexao para ver detalhes
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

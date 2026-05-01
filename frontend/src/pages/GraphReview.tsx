import { useEffect, useState, useCallback } from "react";
import { api, GraphEntity, GraphRelationship, GraphStats } from "../api";

const TYPE_COLORS: Record<string, string> = {
  company: "#3b82f6",
  country: "#ef4444",
  person: "#8b5cf6",
  technology: "#10b981",
  mineral: "#f59e0b",
  product: "#06b6d4",
  organization: "#ec4899",
  event: "#f97316",
};

const PREDICATE_LABELS: Record<string, string> = {
  produces: "produz",
  supplies: "fornece",
  depends_on: "depende de",
  competes_with: "compete com",
  regulates: "regula",
  invests_in: "investe em",
  acquires: "adquire",
  partners_with: "parceria com",
  restricts: "restringe",
  exports: "exporta",
  imports: "importa",
  develops: "desenvolve",
  disrupts: "disrupta",
  sanctions: "sanciona",
};

type Tab = "entities" | "relationships";
type Filter = "staged" | "approved" | "rejected" | "";

export default function GraphReview() {
  const [tab, setTab] = useState<Tab>("entities");
  const [filter, setFilter] = useState<Filter>("staged");
  const [entities, setEntities] = useState<GraphEntity[]>([]);
  const [relationships, setRelationships] = useState<GraphRelationship[]>([]);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [extracting, setExtracting] = useState(false);
  const [extractResult, setExtractResult] = useState<string>("");

  const load = useCallback(async () => {
    try {
      const [statsRes, dataRes] = await Promise.all([
        api.get("/graph/stats"),
        tab === "entities"
          ? api.get("/graph/entities", { params: { status: filter, limit: 200 } })
          : api.get("/graph/relationships", { params: { status: filter, limit: 200 } }),
      ]);
      setStats(statsRes.data);
      if (tab === "entities") {
        setEntities(dataRes.data.entities || []);
      } else {
        setRelationships(dataRes.data.relationships || []);
      }
      setSelectedIds(new Set());
    } catch (e) {
      console.error(e);
    }
  }, [tab, filter]);

  useEffect(() => {
    load();
  }, [load]);

  const handleReview = async (
    type: "entities" | "relationships",
    ids: number[],
    action: "approve" | "reject",
  ) => {
    try {
      await api.post(`/graph/${type}/batch-review`, { ids, action });
      await load();
    } catch (e) {
      console.error(e);
    }
  };

  const handleSingleReview = async (
    type: "entities" | "relationships",
    id: number,
    action: "approve" | "reject",
  ) => {
    try {
      await api.post(`/graph/${type}/${id}/review`, { action });
      await load();
    } catch (e) {
      console.error(e);
    }
  };

  const toggleSelect = (id: number) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    const items = tab === "entities" ? entities : relationships;
    if (selectedIds.size === items.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(items.map((i) => i.id)));
    }
  };

  const handleExtract = async () => {
    setExtracting(true);
    setExtractResult("");
    try {
      const res = await api.post("/graph/extract");
      setExtractResult(
        `Extraidos: ${res.data.extracted} artigos, ${res.data.entities} entidades, ${res.data.relationships} relacoes`
      );
      await load();
    } catch (e: any) {
      const detail = e?.response?.data?.detail || e?.message || "erro desconhecido";
      setExtractResult(`Erro na extracao: ${detail}`);
      console.error(e);
    } finally {
      setExtracting(false);
    }
  };

  const stagedEntities = stats?.entities?.staged || 0;
  const stagedRels = stats?.relationships?.staged || 0;
  const approvedEntities = stats?.entities?.approved || 0;
  const approvedRels = stats?.relationships?.approved || 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Knowledge Graph</h1>
          <p className="text-slate-400 mt-1">
            Revisao de entidades e relacoes extraidas dinamicamente
          </p>
        </div>
        <button
          onClick={handleExtract}
          disabled={extracting}
          className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 rounded-lg text-sm font-medium transition"
        >
          {extracting ? "Extraindo..." : "Extrair Triplas"}
        </button>
      </div>

      {extractResult && (
        <div className="bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-sm text-emerald-400">
          {extractResult}
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 rounded-lg p-4 border border-amber-900/40">
          <div className="text-2xl font-bold text-amber-400">{stagedEntities}</div>
          <div className="text-xs text-slate-400 mt-1">Entidades staged</div>
        </div>
        <div className="bg-slate-900 rounded-lg p-4 border border-amber-900/40">
          <div className="text-2xl font-bold text-amber-400">{stagedRels}</div>
          <div className="text-xs text-slate-400 mt-1">Relacoes staged</div>
        </div>
        <div className="bg-slate-900 rounded-lg p-4 border border-emerald-900/40">
          <div className="text-2xl font-bold text-emerald-400">{approvedEntities}</div>
          <div className="text-xs text-slate-400 mt-1">Entidades aprovadas</div>
        </div>
        <div className="bg-slate-900 rounded-lg p-4 border border-emerald-900/40">
          <div className="text-2xl font-bold text-emerald-400">{approvedRels}</div>
          <div className="text-xs text-slate-400 mt-1">Relacoes aprovadas</div>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
          <button
            onClick={() => { setTab("entities"); setSelectedIds(new Set()); }}
            className={`px-4 py-2 text-sm font-medium transition ${
              tab === "entities" ? "bg-primary-600 text-white" : "text-slate-400 hover:text-white"
            }`}
          >
            Entidades
          </button>
          <button
            onClick={() => { setTab("relationships"); setSelectedIds(new Set()); }}
            className={`px-4 py-2 text-sm font-medium transition ${
              tab === "relationships" ? "bg-primary-600 text-white" : "text-slate-400 hover:text-white"
            }`}
          >
            Relacoes
          </button>
        </div>

        <div className="flex gap-2">
          {(["staged", "approved", "rejected", ""] as Filter[]).map((f) => (
            <button
              key={f || "all"}
              onClick={() => setFilter(f)}
              className={`px-3 py-1 text-xs rounded-full transition ${
                filter === f
                  ? "bg-slate-700 text-white"
                  : "text-slate-500 hover:text-slate-300"
              }`}
            >
              {f || "todos"}
            </button>
          ))}
        </div>

        {selectedIds.size > 0 && filter === "staged" && (
          <div className="flex gap-2 ml-auto">
            <button
              onClick={() => handleReview(tab, [...selectedIds], "approve")}
              className="px-3 py-1 text-xs bg-emerald-600 hover:bg-emerald-700 rounded-full transition"
            >
              Aprovar {selectedIds.size}
            </button>
            <button
              onClick={() => handleReview(tab, [...selectedIds], "reject")}
              className="px-3 py-1 text-xs bg-red-600 hover:bg-red-700 rounded-full transition"
            >
              Rejeitar {selectedIds.size}
            </button>
          </div>
        )}
      </div>

      {tab === "entities" ? (
        <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                {filter === "staged" && (
                  <th className="p-3 w-8">
                    <input
                      type="checkbox"
                      checked={selectedIds.size === entities.length && entities.length > 0}
                      onChange={selectAll}
                      className="rounded border-slate-600"
                    />
                  </th>
                )}
                <th className="p-3 text-left">Entidade</th>
                <th className="p-3 text-left">Tipo</th>
                <th className="p-3 text-left">Pilar</th>
                <th className="p-3 text-right">Mencoes</th>
                <th className="p-3 text-left">Primeira vez</th>
                {filter === "staged" && <th className="p-3 w-24">Acoes</th>}
              </tr>
            </thead>
            <tbody>
              {entities.map((e) => (
                <tr key={e.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  {filter === "staged" && (
                    <td className="p-3">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(e.id)}
                        onChange={() => toggleSelect(e.id)}
                        className="rounded border-slate-600"
                      />
                    </td>
                  )}
                  <td className="p-3">
                    <div className="font-medium">{e.name}</div>
                    <div className="text-xs text-slate-500">{e.canonical}</div>
                  </td>
                  <td className="p-3">
                    <span
                      className="px-2 py-0.5 text-xs rounded-full text-white"
                      style={{ backgroundColor: TYPE_COLORS[e.entity_type] || "#475569" }}
                    >
                      {e.entity_type}
                    </span>
                  </td>
                  <td className="p-3 text-slate-400">{e.pillar || "—"}</td>
                  <td className="p-3 text-right text-slate-300">{e.mention_count}</td>
                  <td className="p-3 text-slate-500 text-xs">
                    {new Date(e.first_seen).toLocaleDateString("pt-BR")}
                  </td>
                  {filter === "staged" && (
                    <td className="p-3">
                      <div className="flex gap-1">
                        <button
                          onClick={() => handleSingleReview("entities", e.id, "approve")}
                          className="p-1 text-emerald-500 hover:text-emerald-400"
                          title="Aprovar"
                        >
                          ✓
                        </button>
                        <button
                          onClick={() => handleSingleReview("entities", e.id, "reject")}
                          className="p-1 text-red-500 hover:text-red-400"
                          title="Rejeitar"
                        >
                          ✕
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
              {entities.length === 0 && (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    Nenhuma entidade {filter || "encontrada"}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                {filter === "staged" && (
                  <th className="p-3 w-8">
                    <input
                      type="checkbox"
                      checked={selectedIds.size === relationships.length && relationships.length > 0}
                      onChange={selectAll}
                      className="rounded border-slate-600"
                    />
                  </th>
                )}
                <th className="p-3 text-left">Sujeito</th>
                <th className="p-3 text-left">Predicado</th>
                <th className="p-3 text-left">Objeto</th>
                <th className="p-3 text-right">Confianca</th>
                <th className="p-3 text-right">Mencoes</th>
                {filter === "staged" && <th className="p-3 w-24">Acoes</th>}
              </tr>
            </thead>
            <tbody>
              {relationships.map((r) => (
                <tr key={r.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  {filter === "staged" && (
                    <td className="p-3">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(r.id)}
                        onChange={() => toggleSelect(r.id)}
                        className="rounded border-slate-600"
                      />
                    </td>
                  )}
                  <td className="p-3 font-medium">{r.subject_name}</td>
                  <td className="p-3">
                    <span className="px-2 py-0.5 text-xs bg-slate-700 rounded-full">
                      {PREDICATE_LABELS[r.predicate] || r.predicate}
                    </span>
                  </td>
                  <td className="p-3 font-medium">{r.object_name}</td>
                  <td className="p-3 text-right">
                    <span className={`${r.confidence >= 0.7 ? "text-emerald-400" : r.confidence >= 0.4 ? "text-amber-400" : "text-red-400"}`}>
                      {(r.confidence * 100).toFixed(0)}%
                    </span>
                  </td>
                  <td className="p-3 text-right text-slate-300">{r.mention_count}</td>
                  {filter === "staged" && (
                    <td className="p-3">
                      <div className="flex gap-1">
                        <button
                          onClick={() => handleSingleReview("relationships", r.id, "approve")}
                          className="p-1 text-emerald-500 hover:text-emerald-400"
                          title="Aprovar"
                        >
                          ✓
                        </button>
                        <button
                          onClick={() => handleSingleReview("relationships", r.id, "reject")}
                          className="p-1 text-red-500 hover:text-red-400"
                          title="Rejeitar"
                        >
                          ✕
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
              {relationships.length === 0 && (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    Nenhuma relacao {filter || "encontrada"}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

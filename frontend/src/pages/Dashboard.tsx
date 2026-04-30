import { useEffect, useState } from "react";
import { api, Prices, MemoryStats, CrossPillarActiveResponse, CrossPillarChain } from "../api";
import StatCard from "../components/StatCard";

type Trends = Record<string, { score: number; trend: string; articles: number }>;

const KIND_MARKERS: Record<string, string> = {
  pattern: "•",
  spike: "🔴",
  correlated_chain: "🔗",
  temporal: "📊",
};

const PILLAR_COLORS: Record<string, string> = {
  tecnologia: "#3b82f6",
  mercados: "#10b981",
  geopolitica: "#f59e0b",
  cadeia: "#8b5cf6",
};

export default function Dashboard() {
  const [prices, setPrices] = useState<Prices>({});
  const [trends, setTrends] = useState<Trends>({});
  const [stats, setStats] = useState<MemoryStats | null>(null);
  const [jobsCount, setJobsCount] = useState(0);
  const [patternsCount, setPatternsCount] = useState(0);
  const [crossPillar, setCrossPillar] = useState<CrossPillarActiveResponse | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [p, t, m, j, pat, cp] = await Promise.all([
          api.get("/prices"),
          api.get("/trends"),
          api.get("/memory/stats"),
          api.get("/jobs"),
          api.get("/patterns"),
          api.get<CrossPillarActiveResponse>("/cross-pillar/active"),
        ]);
        setPrices(p.data.prices || {});
        setTrends(t.data || {});
        setStats(m.data);
        setJobsCount(j.data.total || 0);
        setPatternsCount(pat.data.total || 0);
        setCrossPillar(cp.data);
      } catch (e) {
        console.error(e);
      }
    })();
  }, []);

  const topTrends = Object.entries(trends)
    .filter(([k]) => !["updated_at", "connections"].includes(k))
    .sort(
      ([, a]: any, [, b]: any) => (b?.score || 0) - (a?.score || 0)
    )
    .slice(0, 4);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-slate-400 mt-1">
          Panorama da sua inteligencia pessoal
        </p>
      </div>

      <section>
        <h2 className="text-xs uppercase tracking-wider text-slate-400 mb-3">
          Mercados
        </h2>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {Object.entries(prices).map(([name, data]: any) => (
            <StatCard
              key={name}
              label={name.toUpperCase()}
              value={data.usd ? `$${data.usd.toLocaleString()}` : "—"}
              sub={
                data.usd_24h_change != null
                  ? `${data.usd_24h_change >= 0 ? "+" : ""}${data.usd_24h_change.toFixed(2)}% 24h`
                  : undefined
              }
              accent={
                data.usd_24h_change >= 0 ? "green" : "red"
              }
            />
          ))}
        </div>
      </section>

      {crossPillar && crossPillar.chains.length > 0 && (
        <section>
          <h2 className="text-xs uppercase tracking-wider text-slate-400 mb-3">
            Eventos Cross-Pillar (ultimos {Math.round(crossPillar.window_hours / 24)}d)
          </h2>
          {crossPillar.chains.map((chain: CrossPillarChain, idx: number) => (
            <div
              key={idx}
              className="bg-slate-900 rounded-lg border border-amber-900/40 p-5 space-y-4"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-lg">🔗</span>
                  <h3 className="font-bold">
                    {chain.total_events} sinais correlacionados em {chain.pillars.length} pilares
                  </h3>
                </div>
                <div className="flex gap-1">
                  {chain.pillars.map((p) => (
                    <span
                      key={p}
                      className="px-2 py-0.5 text-xs rounded-full text-white"
                      style={{ backgroundColor: PILLAR_COLORS[p] || "#475569" }}
                    >
                      {crossPillar.pillar_labels[p] || p}
                    </span>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {chain.pillars.map((pillar) => {
                  const events = (chain.events_by_pillar?.[pillar]) ||
                    chain.events.filter((e) => e.pillar === pillar);
                  return (
                    <div key={pillar} className="bg-slate-950 rounded p-3 border border-slate-800">
                      <div className="flex items-center gap-2 mb-2">
                        <div
                          className="w-2 h-2 rounded-full"
                          style={{ backgroundColor: PILLAR_COLORS[pillar] || "#475569" }}
                        />
                        <span className="text-xs uppercase tracking-wider text-slate-400">
                          {crossPillar.pillar_labels[pillar] || pillar}
                        </span>
                        <span className="text-xs text-slate-500 ml-auto">{events.length}</span>
                      </div>
                      <ul className="space-y-1.5 text-sm text-slate-300">
                        {events.slice(0, 4).map((e) => (
                          <li key={e.id} className="flex gap-1.5">
                            <span className="flex-shrink-0">{KIND_MARKERS[e.kind] || "•"}</span>
                            <span className="line-clamp-2">{e.label || e.id}</span>
                          </li>
                        ))}
                        {events.length > 4 && (
                          <li className="text-xs text-slate-500 italic">
                            ...e mais {events.length - 4}
                          </li>
                        )}
                      </ul>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </section>
      )}

      <section>
        <h2 className="text-xs uppercase tracking-wider text-slate-400 mb-3">
          Top trends
        </h2>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {topTrends.map(([cat, info]: any) => (
            <StatCard
              key={cat}
              label={cat.replace(/_/g, " ")}
              value={`${info.score}/100`}
              sub={`${info.articles} artigos · ${info.trend}`}
              accent={
                info.trend === "rising"
                  ? "green"
                  : info.trend === "falling"
                  ? "red"
                  : "blue"
              }
            />
          ))}
        </div>
      </section>

      <section>
        <h2 className="text-xs uppercase tracking-wider text-slate-400 mb-3">
          Atividade
        </h2>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Candidaturas"
            value={jobsCount}
            sub="total registradas"
            accent="amber"
          />
          <StatCard
            label="Patterns"
            value={patternsCount}
            sub="detectados"
            accent="blue"
          />
          <StatCard
            label="Fatos"
            value={stats?.facts_count || 0}
            sub="aprendidos"
            accent="green"
          />
          <StatCard
            label="Mensagens"
            value={stats?.total_messages || 0}
            sub="historico total"
            accent="blue"
          />
        </div>
      </section>
    </div>
  );
}

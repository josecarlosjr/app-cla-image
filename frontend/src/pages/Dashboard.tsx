import { useEffect, useState } from "react";
import { api, Prices, MemoryStats } from "../api";
import StatCard from "../components/StatCard";

type Trends = Record<string, { score: number; trend: string; articles: number }>;

export default function Dashboard() {
  const [prices, setPrices] = useState<Prices>({});
  const [trends, setTrends] = useState<Trends>({});
  const [stats, setStats] = useState<MemoryStats | null>(null);
  const [jobsCount, setJobsCount] = useState(0);
  const [patternsCount, setPatternsCount] = useState(0);

  useEffect(() => {
    (async () => {
      try {
        const [p, t, m, j, pat] = await Promise.all([
          api.get("/prices"),
          api.get("/trends"),
          api.get("/memory/stats"),
          api.get("/jobs"),
          api.get("/patterns"),
        ]);
        setPrices(p.data.prices || {});
        setTrends(t.data || {});
        setStats(m.data);
        setJobsCount(j.data.total || 0);
        setPatternsCount(pat.data.total || 0);
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

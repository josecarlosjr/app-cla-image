import { useEffect, useState } from "react";
import { api, MemoryStats } from "../api";
import StatCard from "../components/StatCard";
import { THEMES, ThemeId, getStoredTheme, applyTheme } from "../utils/theme";

export default function Settings() {
  const [stats, setStats] = useState<MemoryStats | null>(null);
  const [theme, setTheme] = useState<ThemeId>(getStoredTheme());

  useEffect(() => {
    (async () => {
      const { data } = await api.get<MemoryStats>("/memory/stats");
      setStats(data);
    })();
  }, []);

  function chooseTheme(id: ThemeId) {
    applyTheme(id);
    setTheme(id);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Settings &amp; Memoria</h1>
        <p className="text-slate-400 mt-1">
          Estado da memoria persistente do agente
        </p>
      </div>

      <section>
        <h2 className="text-xl font-bold mb-3">Aparencia</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {THEMES.map((t) => {
            const active = t.id === theme;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => chooseTheme(t.id)}
                className={`text-left bg-slate-900 rounded-lg p-4 border transition ${
                  active
                    ? "border-primary-500 ring-1 ring-primary-500"
                    : "border-slate-800 hover:border-slate-700"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium">{t.label}</span>
                  {active && (
                    <span className="text-xs text-primary-400">● ativo</span>
                  )}
                </div>
                <div className="flex gap-1 mb-2">
                  <span
                    className="w-7 h-7 rounded border border-black/10"
                    style={{ background: t.swatch.bg }}
                    aria-hidden
                  />
                  <span
                    className="w-7 h-7 rounded border border-black/10"
                    style={{ background: t.swatch.surface }}
                    aria-hidden
                  />
                  <span
                    className="w-7 h-7 rounded border border-black/10"
                    style={{ background: t.swatch.text }}
                    aria-hidden
                  />
                </div>
                <p className="text-xs text-slate-500">{t.description}</p>
              </button>
            );
          })}
        </div>
        <p className="text-xs text-slate-600 mt-2">
          A preferencia fica salva neste navegador (localStorage) e
          aplica em todas as paginas.
        </p>
      </section>

      <section>
        <h2 className="text-xl font-bold mb-3">Memoria do agente</h2>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Mensagens"
            value={stats?.total_messages || 0}
            sub="historico total"
          />
          <StatCard
            label="User"
            value={stats?.user_messages || 0}
            sub="mensagens enviadas"
            accent="green"
          />
          <StatCard
            label="Agente"
            value={stats?.assistant_messages || 0}
            sub="respostas dadas"
            accent="blue"
          />
          <StatCard
            label="Fatos"
            value={stats?.facts_count || 0}
            sub="aprendidos"
            accent="amber"
          />
        </div>
      </section>

      <section>
        <h2 className="text-xl font-bold mb-3">Fatos aprendidos</h2>
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-5">
          {stats?.facts.length ? (
            <ul className="space-y-2">
              {stats.facts.map((f, i) => (
                <li
                  key={i}
                  className="flex gap-3 items-start border-l-2 border-primary-500 pl-3 py-1"
                >
                  <span className="text-slate-500 text-sm font-mono">
                    {(i + 1).toString().padStart(2, "0")}
                  </span>
                  <span className="text-slate-200">{f}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-slate-500">
              Nenhum fato aprendido ainda. Converse com o agente e ele comeca a
              registrar fatos sobre voce automaticamente.
            </p>
          )}
        </div>
      </section>
    </div>
  );
}

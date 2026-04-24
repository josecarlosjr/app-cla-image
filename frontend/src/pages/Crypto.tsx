import { useEffect, useState } from "react";
import { api, CryptoMover, CryptoScan } from "../api";

function fmt(n: number, digits = 2): string {
  return n.toLocaleString(undefined, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

function fmtPrice(n: number): string {
  if (n >= 1) return `$${fmt(n)}`;
  return `$${n.toLocaleString(undefined, { maximumFractionDigits: 6 })}`;
}

function fmtCap(n: number): string {
  if (n >= 1e12) return `$${fmt(n / 1e12)}T`;
  if (n >= 1e9) return `$${fmt(n / 1e9)}B`;
  if (n >= 1e6) return `$${fmt(n / 1e6)}M`;
  return `$${fmt(n)}`;
}

function ChangeCell({ value }: { value: number }) {
  const color =
    value > 0 ? "text-green-400" : value < 0 ? "text-red-400" : "text-slate-400";
  return (
    <span className={color}>
      {value > 0 ? "+" : ""}
      {fmt(value)}%
    </span>
  );
}

function MoverTable({
  title,
  coins,
  accent,
}: {
  title: string;
  coins: CryptoMover[];
  accent: "green" | "red";
}) {
  const border = accent === "green" ? "border-green-500/30" : "border-red-500/30";
  const heading =
    accent === "green" ? "text-green-400" : "text-red-400";

  return (
    <div className={`bg-slate-900 rounded-lg border ${border} overflow-hidden`}>
      <h2 className={`text-lg font-bold px-4 py-3 ${heading}`}>{title}</h2>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-xs text-slate-500 border-b border-slate-800">
            <th className="text-left px-4 py-2">#</th>
            <th className="text-left px-4 py-2">Moeda</th>
            <th className="text-right px-4 py-2">Preco</th>
            <th className="text-right px-4 py-2">1h</th>
            <th className="text-right px-4 py-2">24h</th>
            <th className="text-right px-4 py-2 hidden md:table-cell">7d</th>
            <th className="text-right px-4 py-2 hidden lg:table-cell">Mkt Cap</th>
          </tr>
        </thead>
        <tbody>
          {coins.map((c) => (
            <tr
              key={c.id}
              className="border-b border-slate-800/50 hover:bg-slate-800/40"
            >
              <td className="px-4 py-2 text-slate-500">
                {c.market_cap_rank ?? "-"}
              </td>
              <td className="px-4 py-2">
                <div className="flex items-center gap-2">
                  {c.image && (
                    <img
                      src={c.image}
                      alt={c.symbol}
                      className="w-5 h-5 rounded-full"
                    />
                  )}
                  <span className="font-medium">{c.symbol}</span>
                  <span className="text-slate-500 hidden sm:inline">
                    {c.name}
                  </span>
                </div>
              </td>
              <td className="px-4 py-2 text-right font-mono">
                {fmtPrice(c.price_usd)}
              </td>
              <td className="px-4 py-2 text-right font-mono">
                <ChangeCell value={c.change_1h} />
              </td>
              <td className="px-4 py-2 text-right font-mono">
                <ChangeCell value={c.change_24h} />
              </td>
              <td className="px-4 py-2 text-right font-mono hidden md:table-cell">
                <ChangeCell value={c.change_7d} />
              </td>
              <td className="px-4 py-2 text-right text-slate-400 hidden lg:table-cell">
                {fmtCap(c.market_cap)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Crypto() {
  const [gainers, setGainers] = useState<CryptoMover[]>([]);
  const [losers, setLosers] = useState<CryptoMover[]>([]);
  const [scans, setScans] = useState<CryptoScan[]>([]);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const [movers, trending] = await Promise.all([
        api.get<{
          gainers: CryptoMover[];
          losers: CryptoMover[];
          updated_at: string;
        }>("/crypto/movers"),
        api.get<{ scans: CryptoScan[] }>("/crypto/trending"),
      ]);
      setGainers(movers.data.gainers || []);
      setLosers(movers.data.losers || []);
      setUpdatedAt(movers.data.updated_at);
      setScans((trending.data.scans || []).reverse());
      setLoading(false);
    })();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500">
        A carregar dados...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Crypto</h1>
        <p className="text-slate-400 mt-1">
          Top movers (1h) + alertas do scanner
          {updatedAt && (
            <span className="text-slate-600 ml-2 text-xs">
              {new Date(updatedAt).toLocaleTimeString()}
            </span>
          )}
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <MoverTable title="Top 10 Gainers (1h)" coins={gainers} accent="green" />
        <MoverTable title="Top 10 Losers (1h)" coins={losers} accent="red" />
      </div>

      <div>
        <h2 className="text-xl font-bold mb-3">Alertas Recentes</h2>
        <p className="text-xs text-slate-500 mb-3">
          Cryptos com +5% em 24h analisadas pelo scanner
        </p>
        <div className="space-y-3">
          {scans.map((s, i) => (
            <div
              key={i}
              className="bg-slate-900 rounded-lg p-5 border border-slate-800"
            >
              <div className="flex items-baseline gap-3 mb-3">
                <h3 className="text-xl font-bold">{s.symbol}</h3>
                <span className="text-slate-400">{s.name}</span>
                <span className="ml-auto text-xs text-slate-500">{s.date}</span>
              </div>
              <div className="flex gap-6 mb-3">
                <div>
                  <p className="text-xs text-slate-400">Preco</p>
                  <p className="text-lg font-medium">{fmtPrice(s.price_usd)}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-400">Variacao 24h</p>
                  <p
                    className={`text-lg font-medium ${
                      s.change_24h >= 0 ? "text-green-400" : "text-red-400"
                    }`}
                  >
                    {s.change_24h >= 0 ? "+" : ""}
                    {s.change_24h.toFixed(2)}%
                  </p>
                </div>
              </div>
              <pre className="text-sm text-slate-300 whitespace-pre-wrap">
                {s.analysis}
              </pre>
            </div>
          ))}
          {scans.length === 0 && (
            <p className="text-slate-500">
              Nenhum alerta ainda. O scanner corre a cada hora.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

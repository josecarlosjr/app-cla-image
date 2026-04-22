import { useEffect, useState } from "react";
import { api, CryptoScan } from "../api";

export default function Crypto() {
  const [scans, setScans] = useState<CryptoScan[]>([]);

  useEffect(() => {
    (async () => {
      const { data } = await api.get<{ scans: CryptoScan[] }>(
        "/crypto/trending"
      );
      setScans((data.scans || []).reverse());
    })();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Crypto trending</h1>
        <p className="text-slate-400 mt-1">
          Historico de cryptos com movimento detectado pelo scanner
        </p>
      </div>

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
                <p className="text-lg font-medium">
                  ${s.price_usd.toLocaleString(undefined, {
                    maximumFractionDigits: 6,
                  })}
                </p>
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
          <p className="text-slate-500">Nenhuma scan ainda.</p>
        )}
      </div>
    </div>
  );
}

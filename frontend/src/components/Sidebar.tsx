import { NavLink } from "react-router-dom";

const items = [
  { to: "/dashboard", label: "Dashboard", icon: "◉" },
  { to: "/map", label: "Mapa", icon: "◈" },
  { to: "/chat", label: "Chat", icon: "✎" },
  { to: "/news", label: "News & Patterns", icon: "≡" },
  { to: "/crypto", label: "Crypto", icon: "◬" },
  { to: "/jobs", label: "Jobs", icon: "◰" },
  { to: "/supply-chain", label: "Supply Chain", icon: "⛓" },
  { to: "/graph", label: "Knowledge Graph", icon: "◇" },
  { to: "/backtesting", label: "Backtesting", icon: "↻" },
  { to: "/settings", label: "Settings", icon: "⚙" },
];

export default function Sidebar() {
  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col">
      <div className="p-6 border-b border-slate-800">
        <h1 className="text-xl font-bold text-primary-500">PIA</h1>
        <p className="text-xs text-slate-400 mt-1">Personal Intelligence Agent</p>
      </div>
      <nav className="flex-1 p-4">
        <ul className="space-y-1">
          {items.map((item) => (
            <li key={item.to}>
              <NavLink
                to={item.to}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-4 py-2 rounded-lg transition ${
                    isActive
                      ? "bg-primary-600 text-white"
                      : "text-slate-300 hover:bg-slate-800"
                  }`
                }
              >
                <span className="text-lg">{item.icon}</span>
                <span>{item.label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <div className="p-4 border-t border-slate-800 text-xs text-slate-500">
        v2.0 · phase 4
      </div>
    </aside>
  );
}

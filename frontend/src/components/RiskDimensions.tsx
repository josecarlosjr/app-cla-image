import { useState } from "react";
import { RiskDimension, RiskDimensionsPanel } from "../api";

// ---------------------------------------------------------------------------
// The four risk dimensions, with a traffic light and an honest tooltip.
// ---------------------------------------------------------------------------
//
// The panel exists because the dashboard used to signal danger only by
// omission: no badge meant calm, but a reader could not tell "measured
// and fine" from "never measured". So every dimension always renders,
// and `unknown` is a visible state rather than an empty space.
//
// All the wording — what a dimension measures, which threshold fired,
// where that threshold comes from — is served by the backend
// (risk_dimensions.py), next to the numbers it describes. This file
// only lays it out. That is deliberate: a threshold and its
// justification drifting apart is exactly the failure this panel is
// meant to prevent.

const STATE_STYLE: Record<string, { dot: string; ring: string; text: string; label: string }> = {
  calm: {
    dot: "bg-emerald-400", ring: "border-emerald-500/40",
    text: "text-emerald-400", label: "calmo",
  },
  watch: {
    dot: "bg-amber-400", ring: "border-amber-500/40",
    text: "text-amber-400", label: "atenção",
  },
  danger: {
    dot: "bg-red-400", ring: "border-red-500/40",
    text: "text-red-400", label: "perigo",
  },
  unknown: {
    dot: "bg-slate-600", ring: "border-slate-700",
    text: "text-slate-500", label: "sem dados",
  },
};

function Tooltip({ dim }: { dim: RiskDimension }) {
  return (
    <div
      role="tooltip"
      className="absolute left-0 top-full mt-2 z-30 w-80 max-w-[85vw] rounded-lg border border-slate-700 bg-slate-950 p-3 shadow-xl text-left"
    >
      <p className="text-xs text-slate-300 leading-relaxed">{dim.measures}</p>
      <p className="mt-2 text-xs text-slate-200 leading-relaxed">
        {dim.applied}
      </p>
      <p className="mt-2 text-[11px] text-slate-400 leading-relaxed">
        <span className="uppercase tracking-wider text-slate-500">
          Âncora
        </span>
        <br />
        {dim.anchor}
      </p>
      {dim.caveat && (
        // The honesty clause. Red thresholds have an external anchor;
        // the amber bands mostly do not, and the tooltip says so rather
        // than implying a rigour that isn't there.
        <p className="mt-2 text-[11px] text-amber-400/80 leading-relaxed border-t border-slate-800 pt-2">
          {dim.caveat}
        </p>
      )}
    </div>
  );
}

function DimensionTile({ dim }: { dim: RiskDimension }) {
  const [open, setOpen] = useState(false);
  const s = STATE_STYLE[dim.state] || STATE_STYLE.unknown;
  return (
    <div
      className="relative"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        aria-label={`${dim.label}: ${s.label}`}
        className={`w-full text-left rounded-lg border ${s.ring} bg-slate-900/60 px-3 py-2.5 hover:bg-slate-800/60 focus:outline-none focus:ring-1 focus:ring-slate-500 transition`}
      >
        <div className="flex items-center gap-2">
          <span className={`inline-block h-2.5 w-2.5 rounded-full ${s.dot}`} />
          <span className="text-[11px] uppercase tracking-wider text-slate-400">
            {dim.label}
          </span>
        </div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className="font-mono text-lg text-slate-100">
            {dim.display}
          </span>
          <span className={`text-xs ${s.text}`}>{s.label}</span>
        </div>
        {dim.ticker && (
          <div className="mt-0.5 font-mono text-[11px] text-slate-500">
            {dim.ticker}
          </div>
        )}
      </button>
      {open && <Tooltip dim={dim} />}
    </div>
  );
}

export function RiskDimensionsGrid({
  panel,
  title = "Risco em 4 dimensões",
  subtitle,
  compact = false,
}: {
  panel: RiskDimensionsPanel;
  title?: string;
  subtitle?: string;
  compact?: boolean;
}) {
  if (!panel?.dimensions?.length) return null;
  const cols = panel.dimensions.length >= 4 ? "lg:grid-cols-4" : "lg:grid-cols-2";
  return (
    <div className="bg-slate-900 rounded-lg p-5 border border-slate-800">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="font-bold text-slate-100">{title}</h2>
        <span className="text-[11px] text-slate-500">
          {subtitle || `âmbito: ${panel.scope}`}
        </span>
      </div>

      <div className={`mt-3 grid grid-cols-1 sm:grid-cols-2 ${cols} gap-3`}>
        {panel.dimensions.map((d) => (
          <DimensionTile key={d.key} dim={d} />
        ))}
      </div>

      {!compact && panel.legend?.length > 0 && (
        // Fixed legend, always visible — not behind a hover. A reader
        // who doesn't know what "EXPLOSIVO" means shouldn't have to
        // discover the tooltip to find out.
        <dl className="mt-4 border-t border-slate-800 pt-3 grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1">
          {panel.legend.map((l) => (
            <div key={l.key} className="flex gap-2 text-[11px] leading-relaxed">
              <dt className="shrink-0 uppercase tracking-wider text-slate-400">
                {l.label}
              </dt>
              <dd className="text-slate-500">{l.short}</dd>
            </div>
          ))}
        </dl>
      )}

      {!compact && (
        <p className="mt-3 text-[11px] text-slate-600 leading-relaxed">
          🟢 calmo · 🟡 atenção · 🔴 perigo · ⚪ sem dados. Passe o rato (ou
          clique) num indicador para ver o que mede, que limiar se aplicou e
          de onde vem esse limiar. Limiares vermelhos têm âncora externa;
          as bandas amarelas são escolhas de desenho e dizem-no.
        </p>
      )}
    </div>
  );
}

export function DimensionBadges({ dims }: { dims: RiskDimension[] }) {
  // Inline form for a table row: dot + label + value, tooltip on hover.
  return (
    <div className="flex flex-wrap gap-1.5">
      {dims.map((d) => {
        const s = STATE_STYLE[d.state] || STATE_STYLE.unknown;
        return (
          <span
            key={d.key}
            title={`${d.label} — ${s.label}. ${d.applied}`}
            className={`inline-flex items-center gap-1 rounded border ${s.ring} px-1.5 py-0.5 text-[10px] ${s.text}`}
          >
            <span className={`inline-block h-1.5 w-1.5 rounded-full ${s.dot}`} />
            {d.label}
            <span className="font-mono text-slate-400">{d.display}</span>
          </span>
        );
      })}
    </div>
  );
}

type Props = {
  label: string;
  value: string | number;
  sub?: string;
  accent?: "blue" | "green" | "red" | "amber";
};

const ACCENTS = {
  blue: "border-blue-500/40",
  green: "border-green-500/40",
  red: "border-red-500/40",
  amber: "border-amber-500/40",
};

export default function StatCard({ label, value, sub, accent = "blue" }: Props) {
  return (
    <div
      className={`bg-slate-900 rounded-lg p-5 border ${ACCENTS[accent]} hover:border-opacity-80 transition`}
    >
      <p className="text-xs uppercase tracking-wider text-slate-400">{label}</p>
      <p className="text-3xl font-bold mt-2">{value}</p>
      {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
    </div>
  );
}

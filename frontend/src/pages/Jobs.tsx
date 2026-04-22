import { useEffect, useState } from "react";
import { api, Job } from "../api";

const STATUSES = ["applied", "interview", "offer", "rejected", "ghosted"];

export default function Jobs() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [form, setForm] = useState({
    company: "",
    role: "",
    url: "",
    status: "applied",
    notes: "",
  });

  async function load() {
    const { data } = await api.get<{ jobs: Job[] }>("/jobs");
    setJobs(data.jobs || []);
  }

  useEffect(() => {
    load();
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!form.company || !form.role) return;
    await api.post("/jobs", form);
    setForm({ company: "", role: "", url: "", status: "applied", notes: "" });
    load();
  }

  async function updateStatus(id: number, status: string) {
    await api.put(`/jobs/${id}`, { status });
    load();
  }

  const statusColour: Record<string, string> = {
    applied: "bg-blue-500/20 text-blue-400",
    interview: "bg-amber-500/20 text-amber-400",
    offer: "bg-green-500/20 text-green-400",
    rejected: "bg-red-500/20 text-red-400",
    ghosted: "bg-slate-500/20 text-slate-400",
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Candidaturas</h1>
        <p className="text-slate-400 mt-1">{jobs.length} total</p>
      </div>

      <form
        onSubmit={create}
        className="bg-slate-900 rounded-lg p-5 border border-slate-800 grid grid-cols-1 md:grid-cols-2 gap-3"
      >
        <input
          value={form.company}
          onChange={(e) => setForm({ ...form, company: e.target.value })}
          placeholder="Empresa"
          className="bg-slate-800 rounded px-3 py-2"
        />
        <input
          value={form.role}
          onChange={(e) => setForm({ ...form, role: e.target.value })}
          placeholder="Cargo"
          className="bg-slate-800 rounded px-3 py-2"
        />
        <input
          value={form.url}
          onChange={(e) => setForm({ ...form, url: e.target.value })}
          placeholder="URL"
          className="bg-slate-800 rounded px-3 py-2 md:col-span-2"
        />
        <select
          value={form.status}
          onChange={(e) => setForm({ ...form, status: e.target.value })}
          className="bg-slate-800 rounded px-3 py-2"
        >
          {STATUSES.map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <button
          type="submit"
          className="bg-primary-600 hover:bg-primary-700 rounded px-4 py-2 font-medium"
        >
          Adicionar
        </button>
      </form>

      <div className="space-y-2">
        {jobs.map((j) => (
          <div
            key={j.id}
            className="bg-slate-900 rounded-lg p-4 border border-slate-800 flex items-center gap-4"
          >
            <span className="text-slate-500 font-mono text-sm">#{j.id}</span>
            <div className="flex-1">
              <p className="font-medium">
                {j.role} <span className="text-slate-400">@ {j.company}</span>
              </p>
              <p className="text-xs text-slate-500">
                updated {new Date(j.updated).toLocaleDateString()}
              </p>
            </div>
            <select
              value={j.status}
              onChange={(e) => updateStatus(j.id, e.target.value)}
              className={`rounded px-3 py-1 text-sm ${statusColour[j.status] || "bg-slate-800"}`}
            >
              {STATUSES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </div>
        ))}
      </div>
    </div>
  );
}

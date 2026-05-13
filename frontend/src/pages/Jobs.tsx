import { useEffect, useState } from "react";
import { api, Job } from "../api";

const STATUSES = ["applied", "interview", "offer", "rejected", "ghosted"];

type EditDraft = {
  company: string;
  role: string;
  url: string;
  status: string;
  notes: string;
};

export default function Jobs() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [form, setForm] = useState<EditDraft>({
    company: "",
    role: "",
    url: "",
    status: "applied",
    notes: "",
  });

  // editingId === null  → all rows in view mode
  // editingId === j.id  → that row is in edit mode, others stay view
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editDraft, setEditDraft] = useState<EditDraft>({
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

  function startEdit(j: Job) {
    setEditingId(j.id);
    setEditDraft({
      company: j.company || "",
      role: j.role || "",
      url: j.url || "",
      status: j.status || "applied",
      notes: j.notes || "",
    });
  }

  function cancelEdit() {
    setEditingId(null);
  }

  async function saveEdit(id: number) {
    if (!editDraft.company || !editDraft.role) return;
    await api.put(`/jobs/${id}`, editDraft);
    setEditingId(null);
    load();
  }

  async function deleteJob(j: Job) {
    const label = `${j.role} @ ${j.company}`;
    const ok = window.confirm(
      `Excluir candidatura "${label}"? Esta acao nao pode ser desfeita.`,
    );
    if (!ok) return;
    await api.delete(`/jobs/${j.id}`);
    if (editingId === j.id) setEditingId(null);
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
        {jobs.map((j) =>
          editingId === j.id ? (
            <div
              key={j.id}
              className="bg-slate-900 rounded-lg p-4 border border-primary-700/60 space-y-3"
            >
              <div className="flex items-center gap-3 text-sm text-slate-500">
                <span className="font-mono">#{j.id}</span>
                <span className="text-primary-400">editando</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <input
                  value={editDraft.company}
                  onChange={(e) =>
                    setEditDraft({ ...editDraft, company: e.target.value })
                  }
                  placeholder="Empresa"
                  className="bg-slate-800 rounded px-3 py-2"
                />
                <input
                  value={editDraft.role}
                  onChange={(e) =>
                    setEditDraft({ ...editDraft, role: e.target.value })
                  }
                  placeholder="Cargo"
                  className="bg-slate-800 rounded px-3 py-2"
                />
                <input
                  value={editDraft.url}
                  onChange={(e) =>
                    setEditDraft({ ...editDraft, url: e.target.value })
                  }
                  placeholder="URL"
                  className="bg-slate-800 rounded px-3 py-2 md:col-span-2"
                />
                <select
                  value={editDraft.status}
                  onChange={(e) =>
                    setEditDraft({ ...editDraft, status: e.target.value })
                  }
                  className="bg-slate-800 rounded px-3 py-2"
                >
                  {STATUSES.map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
                <textarea
                  value={editDraft.notes}
                  onChange={(e) =>
                    setEditDraft({ ...editDraft, notes: e.target.value })
                  }
                  placeholder="Notas"
                  rows={2}
                  className="bg-slate-800 rounded px-3 py-2 md:col-span-2 resize-y"
                />
              </div>
              <div className="flex flex-wrap gap-2 justify-end">
                <button
                  onClick={() => deleteJob(j)}
                  className="text-red-400 hover:text-red-300 text-sm px-3 py-1 rounded border border-red-500/30 hover:border-red-500/60"
                >
                  Excluir
                </button>
                <button
                  onClick={cancelEdit}
                  className="bg-slate-700 hover:bg-slate-600 rounded px-3 py-1 text-sm"
                >
                  Cancelar
                </button>
                <button
                  onClick={() => saveEdit(j.id)}
                  disabled={!editDraft.company || !editDraft.role}
                  className="bg-primary-600 hover:bg-primary-700 disabled:opacity-40 disabled:cursor-not-allowed rounded px-3 py-1 text-sm font-medium"
                >
                  Salvar
                </button>
              </div>
            </div>
          ) : (
            <div
              key={j.id}
              className="bg-slate-900 rounded-lg p-4 border border-slate-800 flex items-center gap-3"
            >
              <span className="text-slate-500 font-mono text-sm shrink-0">
                #{j.id}
              </span>
              <div className="flex-1 min-w-0">
                <p className="font-medium truncate">
                  {j.role}{" "}
                  <span className="text-slate-400">@ {j.company}</span>
                </p>
                <p className="text-xs text-slate-500 truncate">
                  updated {new Date(j.updated).toLocaleDateString()}
                  {j.notes ? (
                    <span className="ml-2 text-slate-600">
                      — {j.notes.length > 80 ? j.notes.slice(0, 80) + "…" : j.notes}
                    </span>
                  ) : null}
                </p>
              </div>
              <select
                value={j.status}
                onChange={(e) => updateStatus(j.id, e.target.value)}
                className={`rounded px-3 py-1 text-sm shrink-0 ${
                  statusColour[j.status] || "bg-slate-800"
                }`}
              >
                {STATUSES.map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
              <button
                onClick={() => startEdit(j)}
                className="text-slate-400 hover:text-slate-100 text-sm px-2 shrink-0"
                title="Editar"
              >
                Editar
              </button>
              <button
                onClick={() => deleteJob(j)}
                className="text-red-500 hover:text-red-400 text-sm px-2 shrink-0"
                title="Excluir"
              >
                Excluir
              </button>
            </div>
          ),
        )}
      </div>
    </div>
  );
}

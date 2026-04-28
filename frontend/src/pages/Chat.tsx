import { useState, useRef, useEffect } from "react";
import { api } from "../api";

type Msg = { role: "user" | "assistant"; content: string };

export default function Chat() {
  const [messages, setMessages] = useState<Msg[]>([
    {
      role: "assistant",
      content:
        "Ola Jose Carlos! Me pergunte algo — posso pesquisar na web, ver precos, analisar patterns ou gerar um digest.",
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function send() {
    const text = input.trim();
    if (!text || loading) return;

    setMessages((m) => [...m, { role: "user", content: text }]);
    setInput("");
    setLoading(true);

    try {
      const { data } = await api.post("/agent/chat", { message: text });
      setMessages((m) => [
        ...m,
        { role: "assistant", content: data.response || "(sem resposta)" },
      ]);
    } catch (e: any) {
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: `Erro: ${e.message || "falha na comunicacao"}`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="h-[calc(100vh-4rem)] flex flex-col">
      <div>
        <h1 className="text-3xl font-bold">Chat</h1>
        <p className="text-slate-400 mt-1 mb-6">
          Converse com o agente (mesmo bot do Telegram)
        </p>
      </div>

      <div className="flex-1 bg-slate-900 rounded-lg border border-slate-800 flex flex-col overflow-hidden">
        <div className="flex-1 overflow-auto p-6 space-y-4">
          {messages.map((m, i) => (
            <div
              key={i}
              className={`flex ${
                m.role === "user" ? "justify-end" : "justify-start"
              }`}
            >
              <div
                className={`max-w-[80%] px-4 py-3 rounded-lg whitespace-pre-wrap ${
                  m.role === "user"
                    ? "bg-primary-600 text-white"
                    : "bg-slate-800 text-slate-100"
                }`}
              >
                {m.content}
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex justify-start">
              <div className="bg-slate-800 px-4 py-3 rounded-lg">
                <span className="text-slate-400">pensando...</span>
              </div>
            </div>
          )}
          <div ref={endRef} />
        </div>

        <div className="border-t border-slate-800 p-4 flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && send()}
            placeholder="Pergunte algo..."
            className="flex-1 bg-slate-800 rounded-lg px-4 py-2 outline-none focus:ring-2 focus:ring-primary-500"
            disabled={loading}
          />
          <button
            onClick={send}
            disabled={loading || !input.trim()}
            className="bg-primary-600 hover:bg-primary-700 disabled:opacity-50 px-6 py-2 rounded-lg font-medium"
          >
            Enviar
          </button>
        </div>
      </div>
    </div>
  );
}

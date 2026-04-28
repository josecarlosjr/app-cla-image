import json
import os
import httpx
from datetime import datetime
from duckduckgo_search import DDGS

DATA_DIR = os.getenv("DATA_DIR", "/data")
JOBS_FILE = os.path.join(DATA_DIR, "jobs_tracker.json")
NOTES_DIR = os.path.join(DATA_DIR, "notes")


# ---------------------------------------------------------------------------
# Helper: jobs persistence
# ---------------------------------------------------------------------------

def _load_jobs() -> list:
    if os.path.exists(JOBS_FILE):
        with open(JOBS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def _save_jobs(jobs: list):
    os.makedirs(os.path.dirname(JOBS_FILE), exist_ok=True)
    with open(JOBS_FILE, "w", encoding="utf-8") as f:
        json.dump(jobs, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Tool functions (async)
# ---------------------------------------------------------------------------

async def web_search(query: str) -> str:
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=5))
        if not results:
            return "Nenhum resultado encontrado."
        output = []
        for r in results:
            output.append(f"**{r['title']}**\n{r['body']}\n{r['href']}")
        return "\n\n".join(output)
    except Exception as e:
        return f"Erro na pesquisa: {e}"


async def get_crypto_price(symbol: str) -> str:
    symbol_map = {
        "btc": "bitcoin", "bitcoin": "bitcoin",
        "eth": "ethereum", "ethereum": "ethereum",
        "sol": "solana", "solana": "solana",
        "ada": "cardano", "cardano": "cardano",
        "xrp": "ripple", "dot": "polkadot",
        "bnb": "binancecoin", "doge": "dogecoin",
        "avax": "avalanche-2", "matic": "matic-network",
        "link": "chainlink",
    }
    coin_id = symbol_map.get(symbol.lower(), symbol.lower())
    url = (
        "https://api.coingecko.com/api/v3/simple/price"
        f"?ids={coin_id}&vs_currencies=usd,eur"
        "&include_24hr_change=true&include_market_cap=true"
    )
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=10)
        data = resp.json()
    if coin_id not in data:
        return f"Crypto '{symbol}' nao encontrada. Tente com o nome completo (ex: bitcoin)."
    info = data[coin_id]
    return json.dumps({
        "symbol": symbol.upper(),
        "price_usd": info.get("usd"),
        "price_eur": info.get("eur"),
        "change_24h": info.get("usd_24h_change"),
        "market_cap_usd": info.get("usd_market_cap"),
    }, indent=2)


async def get_commodity_info(commodity: str) -> str:
    return await web_search(f"{commodity} price today USD market")


async def add_job(
    company: str,
    role: str,
    url: str = "",
    status: str = "applied",
    notes: str = "",
) -> str:
    jobs = _load_jobs()
    job_id = len(jobs) + 1
    job = {
        "id": job_id,
        "company": company,
        "role": role,
        "url": url,
        "status": status,
        "notes": notes,
        "created": datetime.now().isoformat(),
        "updated": datetime.now().isoformat(),
    }
    jobs.append(job)
    _save_jobs(jobs)
    return f"Candidatura #{job_id} adicionada: {role} @ {company} [{status}]"


async def list_jobs(status_filter: str = "") -> str:
    jobs = _load_jobs()
    if status_filter:
        jobs = [j for j in jobs if j["status"].lower() == status_filter.lower()]
    if not jobs:
        return "Nenhuma candidatura encontrada."
    lines = []
    for j in jobs:
        lines.append(
            f"#{j['id']} | {j['role']} @ {j['company']} "
            f"| Status: {j['status']} | {j['updated']}"
        )
        if j.get("notes"):
            lines.append(f"   Notas: {j['notes']}")
    return "\n".join(lines)


async def update_job_status(
    job_id: int, status: str, notes: str = ""
) -> str:
    jobs = _load_jobs()
    for j in jobs:
        if j["id"] == job_id:
            j["status"] = status
            j["updated"] = datetime.now().isoformat()
            if notes:
                j["notes"] = notes
            _save_jobs(jobs)
            return f"Candidatura #{job_id} atualizada para '{status}'."
    return f"Candidatura #{job_id} nao encontrada."


async def save_note(title: str, content: str) -> str:
    os.makedirs(NOTES_DIR, exist_ok=True)
    filename = title.lower().replace(" ", "_").replace("/", "-") + ".md"
    filepath = os.path.join(NOTES_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# {title}\n\n")
        f.write(f"*Criado: {datetime.now().strftime('%Y-%m-%d %H:%M')}*\n\n")
        f.write(content)
    return f"Nota salva: {filename}"


async def list_notes() -> str:
    os.makedirs(NOTES_DIR, exist_ok=True)
    files = [f for f in os.listdir(NOTES_DIR) if f.endswith(".md")]
    if not files:
        return "Nenhuma nota encontrada."
    return "Notas:\n" + "\n".join(f"- {f}" for f in sorted(files))


async def read_note(filename: str) -> str:
    if not filename.endswith(".md"):
        filename += ".md"
    filepath = os.path.join(NOTES_DIR, filename)
    if not os.path.exists(filepath):
        return f"Nota '{filename}' nao encontrada."
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


async def get_current_datetime() -> str:
    now = datetime.now()
    return json.dumps({
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "weekday": now.strftime("%A"),
        "iso": now.isoformat(),
    })


async def scan_trending_crypto() -> str:
    from crypto_scanner import scan_trending
    return await scan_trending()


async def search_patterns(topic: str = "") -> str:
    from pattern_matcher import search_patterns as _search
    return await _search(topic)


async def get_trend_scores() -> str:
    from trend_scorer import get_trend_scores as _get
    return _get()


async def list_facts() -> str:
    from memory import Memory
    m = Memory()
    facts = m.data.get("facts", [])
    if not facts:
        return "Nao ha fatos guardados sobre o usuario."
    return "Fatos aprendidos sobre o usuario:\n" + "\n".join(
        f"- {f}" for f in facts
    )


async def generate_digest_now(mode: str = "morning") -> str:
    from digest import _gather_morning_data, _gather_evening_data, _synthesise
    data = _gather_morning_data() if mode == "morning" else _gather_evening_data()
    return await _synthesise(mode, data)


# ---------------------------------------------------------------------------
# Registry — maps function-call name to the callable
# ---------------------------------------------------------------------------

TOOL_FUNCTIONS = {
    "web_search": web_search,
    "get_crypto_price": get_crypto_price,
    "get_commodity_info": get_commodity_info,
    "add_job": add_job,
    "list_jobs": list_jobs,
    "update_job_status": update_job_status,
    "save_note": save_note,
    "list_notes": list_notes,
    "read_note": read_note,
    "get_current_datetime": get_current_datetime,
    "scan_trending_crypto": scan_trending_crypto,
    "search_patterns": search_patterns,
    "get_trend_scores": get_trend_scores,
    "list_facts": list_facts,
    "generate_digest_now": generate_digest_now,
}


# ---------------------------------------------------------------------------
# Gemini function declarations schema
# ---------------------------------------------------------------------------

TOOLS_SCHEMA = [
    {
        "name": "web_search",
        "description": (
            "Pesquisa na web via DuckDuckGo. "
            "Use para encontrar informacao atual sobre qualquer topico."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Termo de pesquisa",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_crypto_price",
        "description": (
            "Obtem preco atual de uma criptomoeda "
            "(Bitcoin, Ethereum, etc.) via CoinGecko."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "symbol": {
                    "type": "string",
                    "description": "Simbolo ou nome da crypto (ex: btc, ethereum, sol)",
                },
            },
            "required": ["symbol"],
        },
    },
    {
        "name": "get_commodity_info",
        "description": (
            "Obtem informacao sobre commodities "
            "(petroleo Brent, ouro, gas natural, etc.)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "commodity": {
                    "type": "string",
                    "description": "Nome da commodity (ex: brent crude oil, gold, natural gas)",
                },
            },
            "required": ["commodity"],
        },
    },
    {
        "name": "add_job",
        "description": "Adiciona uma nova candidatura ao job tracker.",
        "parameters": {
            "type": "object",
            "properties": {
                "company": {
                    "type": "string",
                    "description": "Nome da empresa",
                },
                "role": {
                    "type": "string",
                    "description": "Cargo/posicao",
                },
                "url": {
                    "type": "string",
                    "description": "URL do anuncio",
                },
                "status": {
                    "type": "string",
                    "description": "Status (applied, interview, offer, rejected, ghosted)",
                },
                "notes": {
                    "type": "string",
                    "description": "Notas adicionais",
                },
            },
            "required": ["company", "role"],
        },
    },
    {
        "name": "list_jobs",
        "description": "Lista candidaturas registradas. Pode filtrar por status.",
        "parameters": {
            "type": "object",
            "properties": {
                "status_filter": {
                    "type": "string",
                    "description": (
                        "Filtro de status "
                        "(applied, interview, offer, rejected, ghosted). "
                        "Vazio para todos."
                    ),
                },
            },
        },
    },
    {
        "name": "update_job_status",
        "description": "Atualiza o status de uma candidatura existente.",
        "parameters": {
            "type": "object",
            "properties": {
                "job_id": {
                    "type": "integer",
                    "description": "ID da candidatura",
                },
                "status": {
                    "type": "string",
                    "description": "Novo status",
                },
                "notes": {
                    "type": "string",
                    "description": "Notas adicionais",
                },
            },
            "required": ["job_id", "status"],
        },
    },
    {
        "name": "save_note",
        "description": "Salva uma nota em arquivo Markdown.",
        "parameters": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Titulo da nota",
                },
                "content": {
                    "type": "string",
                    "description": "Conteudo da nota",
                },
            },
            "required": ["title", "content"],
        },
    },
    {
        "name": "list_notes",
        "description": "Lista todas as notas salvas.",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "read_note",
        "description": "Le o conteudo de uma nota especifica.",
        "parameters": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Nome do arquivo da nota (com ou sem .md)",
                },
            },
            "required": ["filename"],
        },
    },
    {
        "name": "get_current_datetime",
        "description": "Retorna data e hora atual.",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "scan_trending_crypto",
        "description": (
            "Pesquisa as criptomoedas mais populares e com maior "
            "crescimento nas ultimas 24h. Inclui analise de cada moeda."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "search_patterns",
        "description": (
            "Busca padroes detectados pelo sistema de correlacao "
            "multi-fonte. Pode filtrar por topico."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "topic": {
                    "type": "string",
                    "description": "Topico para filtrar (ex: chips, energia, minerais). Vazio para todos.",
                },
            },
        },
    },
    {
        "name": "get_trend_scores",
        "description": (
            "Retorna os scores de tendencia (0-100) por categoria "
            "para o mapa de dependencias geopoliticas."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "list_facts",
        "description": (
            "Lista os fatos aprendidos pelo agente sobre o usuario "
            "(extraidos automaticamente das conversas)."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "generate_digest_now",
        "description": (
            "Gera um digest agora (manha ou noite) sem esperar pelo CronJob. "
            "Util quando o user pede 'me faca um resumo'."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "description": "'morning' (briefing) ou 'evening' (relatorio). Default: morning.",
                },
            },
        },
    },
]

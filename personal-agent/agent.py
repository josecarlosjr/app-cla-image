import os
import logging

import anthropic

from memory import Memory
from tools import TOOL_FUNCTIONS, TOOLS_SCHEMA

logger = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
MODEL_NAME = "claude-sonnet-4-6"
MAX_ITERATIONS = 5

SYSTEM_PROMPT = """\
Voce e meu assistente pessoal de inteligencia. Meu nome e Jose Carlos \
e sou DevOps/Platform Engineer.

Seu papel:
- Me ajudar a monitorar mercados (crypto, commodities, acoes)
- Analisar noticias geopoliticas e seu impacto em tecnologia e investimentos
- Gerenciar minhas candidaturas a emprego (job tracker)
- Guardar e organizar notas e ideias
- Pesquisar informacao na web quando necessario
- Dar contexto e analise, nao apenas dados brutos

Regras:
- Responda SEMPRE em portugues do Brasil
- Seja conciso mas informativo
- Quando falar de precos, inclua sempre a variacao percentual
- Para analise de noticias, foque no impacto global e oportunidades
- Use as ferramentas disponiveis quando precisar de dados atuais
- Nao invente dados — use as tools para obter informacao real
- Quando guardar fatos sobre mim, use a memoria persistente

Contexto persistente:
{facts}

Historico recente:
{history}"""


_client: anthropic.AsyncAnthropic | None = None


def _get_client() -> anthropic.AsyncAnthropic:
    global _client
    if _client is None:
        _client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    return _client


def _build_tools() -> list[dict]:
    return [
        {
            "name": s["name"],
            "description": s["description"],
            "input_schema": s["parameters"],
        }
        for s in TOOLS_SCHEMA
    ]


async def process_message(user_message: str, memory: Memory) -> str:
    if not ANTHROPIC_API_KEY:
        logger.error("ANTHROPIC_API_KEY not set; cannot call Claude")
        return "Erro: ANTHROPIC_API_KEY nao configurada."

    client = _get_client()

    facts = memory.get_facts_summary()
    recent = memory.get_history(limit=20)
    history_str = "\n".join(
        f"{m['role']}: {m['content'][:200]}" for m in recent[-10:]
    )

    system_text = SYSTEM_PROMPT.format(facts=facts, history=history_str)
    tools = _build_tools()

    memory.add_message("user", user_message)

    messages = [{"role": "user", "content": user_message}]

    try:
        response = await client.messages.create(
            model=MODEL_NAME,
            max_tokens=4096,
            system=[{
                "type": "text",
                "text": system_text,
                "cache_control": {"type": "ephemeral"},
            }],
            tools=tools,
            messages=messages,
        )
    except anthropic.APIError as e:
        logger.error("Claude API error: %s", e)
        return "Erro temporario na API. Tente novamente."

    for iteration in range(MAX_ITERATIONS):
        if response.stop_reason != "tool_use":
            break

        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                fn_name = block.name
                fn_args = block.input or {}
                logger.info(
                    "Tool call [%d/%d]: %s(%s)",
                    iteration + 1, MAX_ITERATIONS, fn_name, fn_args,
                )

                tool_fn = TOOL_FUNCTIONS.get(fn_name)
                if tool_fn:
                    try:
                        result = await tool_fn(**fn_args)
                    except Exception as e:
                        result = f"Erro ao executar {fn_name}: {e}"
                else:
                    result = f"Tool '{fn_name}' nao encontrada."

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": str(result),
                })

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

        try:
            response = await client.messages.create(
                model=MODEL_NAME,
                max_tokens=4096,
                system=[{
                    "type": "text",
                    "text": system_text,
                    "cache_control": {"type": "ephemeral"},
                }],
                tools=tools,
                messages=messages,
            )
        except anthropic.APIError as e:
            logger.error("Claude API error during tool loop: %s", e)
            return "Erro temporario na API durante execucao de ferramentas."

    final_text = ""
    for block in response.content:
        if hasattr(block, "text"):
            final_text = block.text
            break

    if not final_text:
        final_text = "Nao consegui gerar uma resposta."

    memory.add_message("assistant", final_text)
    return final_text

"""Fact extractor — runs after each agent conversation.

Uses Claude Haiku 4.5 via forced tool use to detect NEW facts the user
revealed about themselves. Filters duplicates via lowercase + word overlap,
and stores new facts in Memory.facts.

Forced tool use guarantees schema-valid output (no JSON parsing errors).
"""

import logging
import asyncio

from llm import generate_json, MODEL_HAIKU
from memory import Memory

logger = logging.getLogger(__name__)

EXTRACTION_PROMPT = """\
Analise esta conversa e extraia APENAS fatos NOVOS sobre o usuario \
(preferencias, objetivos, situacao pessoal, familia, trabalho, locais, \
planos concretos).

NAO inclua:
- Fatos genericos sobre o mundo
- Perguntas do usuario
- Pedidos de informacao
- Informacao ja conhecida (ver "Fatos ja guardados" abaixo)

Fatos ja guardados:
{existing_facts}

Ultima mensagem do usuario:
{user_message}

Resposta do agente:
{agent_response}

Exemplos de fatos validos:
- "Trabalha como DevOps Engineer"
- "Tem interesse em investir em Bitcoin"
- "Tem uma entrevista na empresa X na proxima semana"
- "Esta aprendendo Kubernetes"

Exemplos INVALIDOS (nao incluir):
- "Perguntou sobre o tempo" (nao e fato do user)
- "Quer saber o preco do BTC" (e uma pergunta, nao um fato)
- "Tem interesse em cripto" (se ja esta nos fatos guardados)

Responda em portugues do Brasil, frases curtas e diretas.
Se nao houver fatos novos, retorne uma lista vazia.
"""

FACT_SCHEMA = {
    "type": "object",
    "properties": {
        "facts": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Lista de fatos novos em portugues do Brasil, "
                "frases curtas e diretas (entre 10 e 300 caracteres cada)."
            ),
        }
    },
    "required": ["facts"],
}


async def extract_facts(
    user_message: str,
    agent_response: str,
    memory: Memory,
) -> list[str]:
    """Extract new facts from a conversation turn and persist them."""

    existing = memory.data.get("facts", [])
    existing_str = "\n".join(f"- {f}" for f in existing) if existing else "(nenhum)"

    prompt = EXTRACTION_PROMPT.format(
        existing_facts=existing_str,
        user_message=user_message[:1000],
        agent_response=agent_response[:1500],
    )

    result = await generate_json(
        prompt=prompt,
        schema=FACT_SCHEMA,
        model=MODEL_HAIKU,
        tool_name="save_facts",
        tool_description="Registra fatos novos aprendidos sobre o usuario.",
        max_tokens=512,
    )

    if not result:
        return []

    new_facts = result.get("facts", [])
    added = []
    existing_lower = {f.lower().strip() for f in existing}

    for fact in new_facts:
        if not isinstance(fact, str):
            continue
        fact = fact.strip()
        if not fact or len(fact) < 10 or len(fact) > 300:
            continue
        if fact.lower() in existing_lower:
            continue
        if _is_similar_to_existing(fact, existing):
            continue

        memory.add_fact(fact)
        added.append(fact)
        existing_lower.add(fact.lower())

    if added:
        logger.info("Fact extractor: +%d new facts: %s", len(added), added)

    return added


def _is_similar_to_existing(new_fact: str, existing: list[str]) -> bool:
    """Simple overlap check to avoid near-duplicates."""
    new_words = set(new_fact.lower().split())
    if len(new_words) < 3:
        return False

    for existing_fact in existing:
        existing_words = set(existing_fact.lower().split())
        if not existing_words:
            continue
        overlap = len(new_words & existing_words) / max(len(new_words), 1)
        if overlap >= 0.7:
            return True

    return False


# ---------------------------------------------------------------------------
# Standalone test entry point
# ---------------------------------------------------------------------------

async def _test():
    memory = Memory()
    facts = await extract_facts(
        user_message="Amanha tenho entrevista na Critical Software em Lisboa",
        agent_response="Boa sorte! Critical Software e uma empresa portuguesa com forte presenca em software crítico.",
        memory=memory,
    )
    print(f"Extracted: {facts}")
    print(f"Total facts: {memory.data.get('facts', [])}")


if __name__ == "__main__":
    asyncio.run(_test())

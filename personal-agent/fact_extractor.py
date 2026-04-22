"""Fact extractor — runs after each agent conversation.

Uses Gemini to detect NEW facts the user revealed about themselves,
filters duplicates via simple lowercase comparison, and stores them
in the Memory.facts list.
"""

import os
import json
import logging
import asyncio

import google.generativeai as genai

from memory import Memory

logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

EXTRACTION_PROMPT = """\
Analisa esta conversa e extrai APENAS factos NOVOS sobre o utilizador \
(preferencias, objectivos, situacao pessoal, familia, trabalho, locais, \
planos concretos).

NAO incluas:
- Factos genericos sobre o mundo
- Perguntas do utilizador
- Pedidos de informacao
- Informacao ja conhecida (ver "Factos ja guardados" abaixo)

Factos ja guardados:
{existing_facts}

Ultima mensagem do utilizador:
{user_message}

Resposta do agente:
{agent_response}

Responde APENAS com JSON valido, sem texto adicional:
{{
    "facts": ["facto 1 em portugues de Portugal, frase curta e directa", "facto 2", ...]
}}

Se nao houver factos novos, retorna: {{"facts": []}}

Exemplos de factos validos:
- "Trabalha em Lisboa"
- "Tem interesse em investir em Bitcoin"
- "Tem uma entrevista na empresa X na proxima semana"
- "Esta a aprender Portugues de Portugal"

Exemplos INVALIDOS (nao incluir):
- "Perguntou sobre o tempo" (nao e facto do user)
- "Quer saber o preco do BTC" (e uma pergunta, nao um facto)
- "Tem interesse em cripto" (se ja esta nos factos guardados)
"""


async def extract_facts(
    user_message: str,
    agent_response: str,
    memory: Memory,
) -> list[str]:
    """Extract new facts from a conversation turn and persist them."""

    if not GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set; skipping fact extraction")
        return []

    existing = memory.data.get("facts", [])
    existing_str = "\n".join(f"- {f}" for f in existing) if existing else "(nenhum)"

    prompt = EXTRACTION_PROMPT.format(
        existing_facts=existing_str,
        user_message=user_message[:1000],
        agent_response=agent_response[:1500],
    )

    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(
            "gemini-2.0-flash",
            generation_config={"response_mime_type": "application/json"},
        )
        response = await asyncio.to_thread(model.generate_content, prompt)
        text = (response.text or "").strip()
    except Exception as e:
        logger.error("Fact extraction Gemini error: %s", e)
        return []

    try:
        data = json.loads(text)
        new_facts = data.get("facts", [])
    except json.JSONDecodeError:
        logger.warning("Fact extraction: invalid JSON: %s", text[:200])
        return []

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

import os
import logging

import google.generativeai as genai

from memory import Memory
from tools import TOOL_FUNCTIONS, TOOLS_SCHEMA

logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = "gemini-2.0-flash"
MAX_ITERATIONS = 5

SYSTEM_PROMPT = """\
Tu es o meu assistente pessoal de inteligencia. O meu nome e Jose Carlos \
e sou DevOps/Platform Engineer baseado em Portugal.

O teu papel:
- Ajudar-me a monitorizar mercados (crypto, commodities, acoes)
- Analisar noticias geopoliticas e o seu impacto em tecnologia e investimentos
- Gerir as minhas candidaturas a emprego (job tracker)
- Guardar e organizar notas e ideias
- Pesquisar informacao na web quando necessario
- Dar contexto e analise, nao apenas dados brutos

Regras:
- Responde SEMPRE em portugues de Portugal (nao brasileiro)
- Se conciso mas informativo
- Quando falares de precos, inclui sempre a variacao percentual
- Para analise de noticias, foca no impacto para Portugal e Europa
- Usa as ferramentas disponiveis quando precisares de dados actuais
- Nao inventes dados — usa as tools para obter informacao real
- Quando guardares factos sobre mim, usa a memoria persistente

Contexto persistente:
{facts}

Historico recente:
{history}"""


# ---------------------------------------------------------------------------
# Build Gemini-compatible tool declarations from TOOLS_SCHEMA
# ---------------------------------------------------------------------------

_TYPE_MAP = {
    "string": genai.protos.Type.STRING,
    "integer": genai.protos.Type.INTEGER,
    "number": genai.protos.Type.NUMBER,
    "boolean": genai.protos.Type.BOOLEAN,
    "array": genai.protos.Type.ARRAY,
    "object": genai.protos.Type.OBJECT,
}


def _build_gemini_tools():
    declarations = []
    for schema in TOOLS_SCHEMA:
        props = schema.get("parameters", {}).get("properties", {})
        gemini_props = {
            k: genai.protos.Schema(
                type=_TYPE_MAP.get(v.get("type", "string"), genai.protos.Type.STRING),
                description=v.get("description", ""),
            )
            for k, v in props.items()
        }
        declarations.append(
            genai.protos.FunctionDeclaration(
                name=schema["name"],
                description=schema["description"],
                parameters=genai.protos.Schema(
                    type=genai.protos.Type.OBJECT,
                    properties=gemini_props,
                    required=schema.get("parameters", {}).get("required", []),
                ),
            )
        )
    return genai.protos.Tool(function_declarations=declarations)


# ---------------------------------------------------------------------------
# Main agentic loop
# ---------------------------------------------------------------------------

async def process_message(user_message: str, memory: Memory) -> str:
    genai.configure(api_key=GEMINI_API_KEY)

    facts = memory.get_facts_summary()
    recent = memory.get_history(limit=20)
    history_str = "\n".join(
        f"{m['role']}: {m['content'][:200]}" for m in recent[-10:]
    )

    system = SYSTEM_PROMPT.format(facts=facts, history=history_str)

    model = genai.GenerativeModel(
        model_name=MODEL_NAME,
        system_instruction=system,
        tools=[_build_gemini_tools()],
    )

    memory.add_message("user", user_message)

    chat = model.start_chat()
    response = chat.send_message(user_message)

    for iteration in range(MAX_ITERATIONS):
        function_calls = [
            part for part in response.parts
            if part.function_call and part.function_call.name
        ]
        if not function_calls:
            break

        function_responses = []
        for fc in function_calls:
            fn_name = fc.function_call.name
            fn_args = dict(fc.function_call.args) if fc.function_call.args else {}
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

            function_responses.append(
                genai.protos.Part(
                    function_response=genai.protos.FunctionResponse(
                        name=fn_name,
                        response={"result": result},
                    )
                )
            )

        response = chat.send_message(
            genai.protos.Content(parts=function_responses)
        )

    final_text = response.text if response.text else "Nao consegui gerar uma resposta."
    memory.add_message("assistant", final_text)
    return final_text


# ---------------------------------------------------------------------------
# Stub para migracao futura para Claude API (anthropic SDK)
# ---------------------------------------------------------------------------
#
# import anthropic
#
# client = anthropic.Anthropic()  # usa ANTHROPIC_API_KEY do env
#
# async def process_message_claude(user_message: str, memory: Memory) -> str:
#     messages = [
#         {"role": m["role"], "content": m["content"]}
#         for m in memory.get_history()
#     ]
#     messages.append({"role": "user", "content": user_message})
#
#     # Primeira chamada com prompt caching (beta)
#     response = client.messages.create(
#         model="claude-sonnet-4-20250514",
#         max_tokens=4096,
#         system=[{
#             "type": "text",
#             "text": SYSTEM_PROMPT.format(
#                 facts=memory.get_facts_summary(), history=""
#             ),
#             "cache_control": {"type": "ephemeral"},   # prompt caching
#         }],
#         tools=[
#             {
#                 "name": s["name"],
#                 "description": s["description"],
#                 "input_schema": s["parameters"],
#             }
#             for s in TOOLS_SCHEMA
#         ],
#         messages=messages,
#     )
#
#     # Agentic loop com Claude:
#     for _ in range(MAX_ITERATIONS):
#         if response.stop_reason != "tool_use":
#             break
#
#         tool_results = []
#         for block in response.content:
#             if block.type == "tool_use":
#                 fn = TOOL_FUNCTIONS.get(block.name)
#                 result = await fn(**block.input) if fn else "Tool not found"
#                 tool_results.append({
#                     "type": "tool_result",
#                     "tool_use_id": block.id,
#                     "content": result,
#                 })
#
#         messages.append({"role": "assistant", "content": response.content})
#         messages.append({"role": "user", "content": tool_results})
#
#         response = client.messages.create(
#             model="claude-sonnet-4-20250514",
#             max_tokens=4096,
#             system=[{
#                 "type": "text",
#                 "text": SYSTEM_PROMPT.format(
#                     facts=memory.get_facts_summary(), history=""
#                 ),
#                 "cache_control": {"type": "ephemeral"},
#             }],
#             tools=[
#                 {
#                     "name": s["name"],
#                     "description": s["description"],
#                     "input_schema": s["parameters"],
#                 }
#                 for s in TOOLS_SCHEMA
#             ],
#             messages=messages,
#         )
#
#     # Extrair texto final
#     final = next(
#         (b.text for b in response.content if b.type == "text"), ""
#     )
#     memory.add_message("assistant", final)
#     return final

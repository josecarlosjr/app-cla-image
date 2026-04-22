import os
import logging

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

from agent import process_message
from fact_extractor import extract_facts
from memory import Memory

DATA_DIR = os.getenv("DATA_DIR", "/data")
LOG_FILE = os.path.join(DATA_DIR, "agent.log")

os.makedirs(DATA_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ALLOWED_USER_ID = int(os.getenv("TELEGRAM_ALLOWED_USER_ID", "0"))

memory = Memory()


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

def _is_allowed(update: Update) -> bool:
    return update.effective_user is not None and update.effective_user.id == ALLOWED_USER_ID


async def _send_long(update: Update, text: str):
    for i in range(0, len(text), 4096):
        await update.message.reply_text(text[i : i + 4096])


# ---------------------------------------------------------------------------
# Message handler
# ---------------------------------------------------------------------------

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        logger.warning("Unauthorized access attempt: %s", update.effective_user.id)
        return

    user_text = update.message.text
    logger.info("Message from %s: %s", update.effective_user.id, user_text[:100])

    await update.message.chat.send_action("typing")

    try:
        response = await process_message(user_text, memory)
        await _send_long(update, response)

        try:
            await extract_facts(user_text, response, memory)
        except Exception as e:
            logger.warning("Fact extraction failed: %s", e)
    except Exception as e:
        logger.error("Error processing message: %s", e, exc_info=True)
        await update.message.reply_text(f"Erro ao processar mensagem: {e}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    await update.message.reply_text(
        "Ola! Sou o teu assistente pessoal de inteligencia.\n\n"
        "Posso ajudar-te com:\n"
        "- Pesquisas na web\n"
        "- Precos de crypto e commodities\n"
        "- Gestao de candidaturas\n"
        "- Notas e organizacao\n\n"
        "Envia-me qualquer mensagem para comecar!"
    )


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    history = memory.get_history(limit=1000)
    facts = memory.data.get("facts", [])
    user_msgs = sum(1 for m in history if m["role"] == "user")
    assistant_msgs = sum(1 for m in history if m["role"] == "assistant")
    await update.message.reply_text(
        f"Estatisticas:\n"
        f"- Mensagens do utilizador: {user_msgs}\n"
        f"- Respostas do agente: {assistant_msgs}\n"
        f"- Factos guardados: {len(facts)}\n"
        f"- Total no historico: {len(history)}"
    )


async def cmd_clear(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    memory.clear_history()
    await update.message.reply_text(
        "Historico limpo. Os factos guardados foram mantidos."
    )


async def cmd_myid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"O teu Telegram ID e: {update.effective_user.id}"
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    await update.message.reply_text(
        "Comandos disponiveis:\n\n"
        "/start  -  Mensagem de boas-vindas\n"
        "/stats  -  Estatisticas de uso\n"
        "/clear  -  Limpar historico (mantem factos)\n"
        "/myid   -  Ver o teu Telegram ID\n"
        "/help   -  Esta mensagem\n\n"
        "Envia qualquer mensagem de texto para interagir com o agente."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if not TELEGRAM_BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN not set")
        return
    if not ALLOWED_USER_ID:
        logger.error("TELEGRAM_ALLOWED_USER_ID not set")
        return

    logger.info("Starting bot. Allowed user: %s", ALLOWED_USER_ID)

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("clear", cmd_clear))
    app.add_handler(CommandHandler("myid", cmd_myid))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message)
    )

    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()

"""Telegram message formatting.

Telegram's legacy `Markdown` parse mode is brittle: LLMs trained on
standard CommonMark frequently emit `**bold**`, but the legacy parser
expects `*bold*` (single asterisk) and either renders the doubled
asterisks literally or rejects the whole message with HTTP 400
("can't parse entities"). Special characters like `_` `[` `]` in URLs
or article titles trigger the same failure mode.

To remove that whole class of bug, every outbound Telegram message is
run through `to_telegram_html` and sent with `parse_mode="HTML"`. The
helper:

  - HTML-escapes the entire string first (so `<`, `>`, `&` from sources
    or article titles can never break the message)
  - then re-introduces only the small set of inline tags Telegram
    supports (`<b>`, `<code>`) by mapping common markdown spellings to
    them

Both `**bold**` and `*bold*` map to `<b>`. Our prompt convention is
the Telegram-legacy `*HEADER:*`, but Sonnet/Haiku regularly drift to
the standard `**HEADER:**`. We intentionally collapse both to bold:
italic emphasis is essentially never wanted in a news brief, and
treating both spellings the same way means the user sees consistent
formatting regardless of which the model picked.
"""

import re

_BOLD_DOUBLE_STAR = re.compile(r"\*\*([^*\n]+?)\*\*")
_BOLD_DOUBLE_UNDER = re.compile(r"__([^_\n]+?)__")
_BOLD_SINGLE_STAR = re.compile(r"(?<!\*)\*(?!\*)([^*\n]+?)(?<!\*)\*(?!\*)")
_INLINE_CODE = re.compile(r"`([^`\n]+?)`")


def to_telegram_html(text: str) -> str:
    """Convert a markdown-flavoured message to Telegram-safe HTML."""
    safe = (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )
    safe = _BOLD_DOUBLE_STAR.sub(r"<b>\1</b>", safe)
    safe = _BOLD_DOUBLE_UNDER.sub(r"<b>\1</b>", safe)
    safe = _BOLD_SINGLE_STAR.sub(r"<b>\1</b>", safe)
    safe = _INLINE_CODE.sub(r"<code>\1</code>", safe)
    return safe

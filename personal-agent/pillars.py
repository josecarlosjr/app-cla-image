"""Pillar definitions for cross-pillar correlation engine.

The application tracks 4 strategic pillars; each pillar groups one or more
news categories. Cross-pillar events occur when the same underlying
phenomenon (e.g., an export ban) produces signals across 3+ pillars
simultaneously.

This module is the single source of truth for category→pillar mapping.
"""

PILLARS = ["tecnologia", "mercados", "geopolitica", "cadeia"]

PILLAR_LABELS = {
    "tecnologia": "Tecnologia & IA",
    "mercados": "Mercados & Financas",
    "geopolitica": "Geopolitica & Defesa",
    "cadeia": "Cadeia de Suprimentos",
}

CATEGORY_TO_PILLAR = {
    "chips_ia": "tecnologia",
    "ciencia": "tecnologia",
    "ciberseguranca": "tecnologia",
    "financas": "mercados",
    "geopolitica": "geopolitica",
    "espaco_defesa": "geopolitica",
    "minerais": "cadeia",
    "energia": "cadeia",
    "cadeia_suprimentos": "cadeia",
}


def category_to_pillar(category: str) -> str | None:
    return CATEGORY_TO_PILLAR.get(category)


def categories_to_pillars(categories: list[str]) -> set[str]:
    return {p for c in categories if (p := CATEGORY_TO_PILLAR.get(c))}

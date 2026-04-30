"""Supply chain knowledge graph — static seed + query helpers.

Models the dependency chain:
  Energia → Transformadores → Redes de Transmissao
  Paineis Solares → Prata, Litio (baterias)
  Redes + Paineis → Cobre
  Componentes eletricos → Chips IA → Terras raras → Estanho
  Semicondutor → Memoria RAM

Seeded once on first run. Updated dynamically by supply_chain_analyzer
(Onda 6) via article mention extraction.
"""

import logging
from database import (
    get_supply_chain_nodes,
    get_supply_chain_edges,
    get_supply_chain_mention_counts,
    seed_supply_chain,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Seed data — the user's mineral/component dependency graph
# ---------------------------------------------------------------------------

SEED_NODES = [
    # --- Products / Infrastructure ---
    {"id": "energia_renovavel", "name": "Energia Renovavel", "type": "product",
     "keywords": ["renewable energy", "energia renovavel", "clean energy", "energia limpa"]},
    {"id": "energia_tradicional", "name": "Energia Tradicional", "type": "product",
     "keywords": ["fossil fuel", "natural gas", "coal power", "oil power", "gas natural"]},
    {"id": "rede_transmissao", "name": "Rede de Transmissao", "type": "infra",
     "keywords": ["transmission line", "power grid", "grid infrastructure",
                  "rede de transmissao", "rede eletrica", "power line"]},
    {"id": "transformador", "name": "Transformador", "type": "infra",
     "keywords": ["transformer", "power transformer", "grid transformer",
                  "transformador", "substation"]},
    # --- Components ---
    {"id": "painel_solar", "name": "Painel Solar", "type": "component",
     "keywords": ["solar panel", "photovoltaic", "PV module", "solar cell",
                  "painel solar", "painel fotovoltaico"]},
    {"id": "turbina_eolica", "name": "Turbina Eolica", "type": "component",
     "keywords": ["wind turbine", "wind power", "wind farm", "turbina eolica",
                  "eolica", "offshore wind"]},
    {"id": "bateria_litio", "name": "Bateria de Litio", "type": "component",
     "keywords": ["lithium battery", "Li-ion", "lithium-ion", "BESS",
                  "battery storage", "bateria de litio", "energy storage",
                  "EV battery", "LFP", "NMC"]},
    {"id": "chip_ia", "name": "Chip de IA", "type": "component",
     "keywords": ["AI chip", "GPU", "TPU", "NPU", "AI accelerator",
                  "chip de IA", "H100", "B200", "Blackwell", "Hopper"]},
    {"id": "chip_quantico", "name": "Chip Quantico", "type": "component",
     "keywords": ["quantum chip", "quantum processor", "qubit",
                  "chip quantico", "quantum computing", "quantum computer"]},
    {"id": "memoria_ram", "name": "Memoria RAM", "type": "component",
     "keywords": ["DRAM", "HBM", "HBM3", "HBM4", "memory chip",
                  "memoria RAM", "SRAM", "DDR5"]},
    {"id": "semicondutor", "name": "Semicondutor", "type": "component",
     "keywords": ["semiconductor", "wafer", "fab", "foundry", "TSMC",
                  "Samsung Foundry", "Intel Foundry", "semicondutor",
                  "chip fabrication", "nanometer", "EUV"]},
    {"id": "fibra_otica", "name": "Fibra Otica", "type": "component",
     "keywords": ["fiber optic", "optical fiber", "fibra otica",
                  "submarine cable", "data cable"]},
    # --- Minerals ---
    {"id": "litio", "name": "Litio", "type": "mineral",
     "keywords": ["lithium", "litio", "Li2CO3", "lithium carbonate",
                  "spodumene", "lithium hydroxide", "LiOH"]},
    {"id": "cobre", "name": "Cobre", "type": "mineral",
     "keywords": ["copper", "cobre", "Cu", "copper wire", "copper mining"]},
    {"id": "prata", "name": "Prata", "type": "mineral",
     "keywords": ["silver", "prata", "Ag", "silver paste", "silver price"]},
    {"id": "terras_raras", "name": "Terras Raras", "type": "mineral",
     "keywords": ["rare earth", "neodymium", "dysprosium", "praseodymium",
                  "terras raras", "rare earth elements", "REE",
                  "cerium", "lanthanum", "yttrium"]},
    {"id": "estanho", "name": "Estanho", "type": "mineral",
     "keywords": ["tin", "estanho", "Sn", "solder", "tin solder",
                  "tin mining", "solda"]},
    {"id": "cobalto", "name": "Cobalto", "type": "mineral",
     "keywords": ["cobalt", "cobalto", "Co", "cobalt mining"]},
    {"id": "niquel", "name": "Niquel", "type": "mineral",
     "keywords": ["nickel", "niquel", "Ni", "nickel mining",
                  "stainless steel", "nickel sulfate"]},
    {"id": "silicio", "name": "Silicio", "type": "mineral",
     "keywords": ["silicon", "silicio", "Si", "polysilicon",
                  "silicon wafer", "metallurgical silicon"]},
    {"id": "galio", "name": "Galio", "type": "mineral",
     "keywords": ["gallium", "galio", "Ga", "gallium arsenide", "GaAs",
                  "gallium nitride", "GaN"]},
    {"id": "germanio", "name": "Germanio", "type": "mineral",
     "keywords": ["germanium", "germanio", "Ge",
                  "germanium dioxide", "fiber optic germanium"]},
    {"id": "uranio", "name": "Uranio", "type": "mineral",
     "keywords": ["uranium", "uranio", "U3O8", "yellowcake",
                  "nuclear fuel", "uranium mining", "enrichment"]},
    {"id": "platina", "name": "Platina", "type": "mineral",
     "keywords": ["platinum", "platina", "Pt", "PGM",
                  "platinum group", "palladium"]},
]

SEED_EDGES = [
    # Energia renovavel depende de componentes
    ("energia_renovavel", "painel_solar", "requires"),
    ("energia_renovavel", "turbina_eolica", "requires"),
    ("energia_renovavel", "bateria_litio", "requires"),
    ("energia_renovavel", "rede_transmissao", "requires"),
    ("energia_renovavel", "transformador", "requires"),
    # Energia tradicional depende de infra
    ("energia_tradicional", "transformador", "requires"),
    ("energia_tradicional", "rede_transmissao", "requires"),
    # Infra de transmissao depende de minerais
    ("rede_transmissao", "cobre", "requires"),
    ("transformador", "cobre", "requires"),
    ("transformador", "silicio", "requires"),
    # Painel solar depende de minerais
    ("painel_solar", "prata", "requires"),
    ("painel_solar", "silicio", "requires"),
    ("painel_solar", "cobre", "requires"),
    # Turbina eolica depende de minerais
    ("turbina_eolica", "terras_raras", "requires"),
    ("turbina_eolica", "cobre", "requires"),
    # Bateria de litio depende de minerais
    ("bateria_litio", "litio", "requires"),
    ("bateria_litio", "cobalto", "requires"),
    ("bateria_litio", "niquel", "requires"),
    ("bateria_litio", "cobre", "requires"),
    # Chip de IA depende de componentes e minerais
    ("chip_ia", "semicondutor", "requires"),
    ("chip_ia", "terras_raras", "requires"),
    ("chip_ia", "memoria_ram", "requires"),
    # Chip quantico depende de componentes e minerais
    ("chip_quantico", "semicondutor", "requires"),
    ("chip_quantico", "terras_raras", "requires"),
    ("chip_quantico", "galio", "requires"),
    # Memoria RAM depende de componentes e minerais
    ("memoria_ram", "semicondutor", "requires"),
    ("memoria_ram", "estanho", "requires"),
    # Semicondutor depende de minerais
    ("semicondutor", "silicio", "requires"),
    ("semicondutor", "galio", "requires"),
    ("semicondutor", "germanio", "requires"),
    ("semicondutor", "estanho", "requires"),
    ("semicondutor", "cobre", "requires"),
    # Fibra otica depende de minerais
    ("fibra_otica", "germanio", "requires"),
    ("fibra_otica", "silicio", "requires"),
    # Nuclear depende de uranio
    ("energia_tradicional", "uranio", "requires"),
    # Catalise e hidrogenio verde
    ("energia_renovavel", "platina", "requires"),
]


# ---------------------------------------------------------------------------
# Seed on first access
# ---------------------------------------------------------------------------

def ensure_seeded() -> None:
    nodes = get_supply_chain_nodes()
    if nodes:
        return
    logger.info("Seeding supply chain knowledge graph...")
    seed_supply_chain(SEED_NODES, SEED_EDGES)


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_full_graph() -> dict:
    ensure_seeded()
    nodes = get_supply_chain_nodes()
    edges = get_supply_chain_edges()
    mention_counts = get_supply_chain_mention_counts(hours=168)

    for node in nodes:
        nid = node["id"]
        mc = mention_counts.get(nid, {"total": 0, "sentiments": {}})
        node["mentions_7d"] = mc["total"]
        node["sentiments"] = mc.get("sentiments", {})

    return {"nodes": nodes, "edges": edges}


def get_dependents(node_id: str) -> list[str]:
    edges = get_supply_chain_edges()
    return [e["src"] for e in edges if e["dst"] == node_id]


def get_dependencies(node_id: str) -> list[str]:
    edges = get_supply_chain_edges()
    return [e["dst"] for e in edges if e["src"] == node_id]


def get_impact_chain(node_id: str, max_depth: int = 4) -> list[dict]:
    edges = get_supply_chain_edges()

    adj: dict[str, list[str]] = {}
    for e in edges:
        adj.setdefault(e["dst"], []).append(e["src"])

    visited: set[str] = set()
    chain: list[dict] = []

    def _walk(nid: str, depth: int):
        if depth > max_depth or nid in visited:
            return
        visited.add(nid)
        for dependent in adj.get(nid, []):
            chain.append({"from": nid, "to": dependent, "depth": depth})
            _walk(dependent, depth + 1)

    _walk(node_id, 1)
    return chain

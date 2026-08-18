"""Peça 2 — máquina de estados de bolha (Onda 13 Fase 3, research).

Orquestra a Peça 1 (GSADF calibrado: explosive?) e a Peça 3 (reversão:
entrada?) numa máquina de estados por ponto no tempo. O ponto CENTRAL do
design: BOLHA_ATIVA PERSISTE mesmo quando a Peça 1 adormece (o GSADF
apaga antes do topo) — só a Peça 3 (reversão real) a termina.

  Estados: CALMO, SUSPEITA, BOLHA_ATIVA, REVERSAO

  Transições:
    CALMO      → SUSPEITA:     Peça1 acende (explosive)
    SUSPEITA   → BOLHA_ATIVA:  Peça1 sustentada >= `sustain` janelas seguidas
    SUSPEITA   → CALMO:        Peça1 apaga antes de confirmar (falso alarme)
    BOLHA_ATIVA→ REVERSAO:     Peça3 dispara (entrada em reversão)
    BOLHA_ATIVA persiste:      mesmo com Peça1 apagada, até a Peça3 disparar
    REVERSAO   → CALMO:        drawdown recupera < `rearm`

Contexto (a Peça 3 é sem-contexto; só conta como REVERSAO se vínhamos de
BOLHA_ATIVA): uma reversão sem bolha confirmada antes é ignorada aqui —
é o que dá significado à deteção (uma queda de 50% só é "estouro de
bolha" se houve bolha).

Função pura sobre séries JÁ ALINHADAS (o alinhamento das duas grelhas —
GSADF mensal vs reversão diária — é do caller). Testável sem DB.
"""
from __future__ import annotations

CALMO = "CALMO"
SUSPEITA = "SUSPEITA"
BOLHA_ATIVA = "BOLHA_ATIVA"
REVERSAO = "REVERSAO"

DEFAULT_SUSTAIN = 2       # janelas Peça1 consecutivas p/ confirmar bolha
DEFAULT_REARM = 0.20      # drawdown abaixo disto encerra a REVERSAO


def run_state_machine(
    dates: list,
    p1_explosive: list,
    p3_entry: list,
    drawdown: list,
    *,
    sustain: int = DEFAULT_SUSTAIN,
    rearm: float = DEFAULT_REARM,
) -> list[dict]:
    """Devolve [{ts, state}, ...] por ponto. Arrays alinhados no mesmo
    índice temporal (tipicamente a grelha da Peça 1).

    ``p1_explosive[i]``: Peça 1 acesa nesse ponto (bool).
    ``p3_entry[i]``:     entrada em reversão da Peça 3 nesse ponto (bool).
    ``drawdown[i]``:     drawdown da Peça 3 nesse ponto (float, p/ o re-arme).
    """
    n = len(dates)
    if not (len(p1_explosive) == len(p3_entry) == len(drawdown) == n):
        raise ValueError("series desalinhadas")

    out: list[dict] = []
    state = CALMO
    consec = 0   # janelas Peça1 acesas consecutivas enquanto em SUSPEITA

    for i in range(n):
        expl = bool(p1_explosive[i])
        entry = bool(p3_entry[i])
        dd = drawdown[i]

        if state == CALMO:
            if expl:
                state = SUSPEITA
                consec = 1

        elif state == SUSPEITA:
            if expl:
                consec += 1
                if consec >= sustain:
                    state = BOLHA_ATIVA
            else:
                state = CALMO          # falso alarme
                consec = 0

        elif state == BOLHA_ATIVA:
            if entry:
                state = REVERSAO       # Peça3 termina a bolha
            # else: PERSISTE — mesmo com expl=False (design central)

        elif state == REVERSAO:
            if dd is not None and dd < rearm:
                state = CALMO          # recuperou

        out.append({"ts": dates[i], "state": state})
    return out


def extract_transitions(states: list[dict]) -> list[dict]:
    """Compacta a série de estados nas TRANSIÇÕES (from→to com data)."""
    trans: list[dict] = []
    prev = None
    for r in states:
        if prev is None:
            trans.append({"ts": r["ts"], "from": None, "to": r["state"]})
        elif r["state"] != prev:
            trans.append({"ts": r["ts"], "from": prev, "to": r["state"]})
        prev = r["state"]
    return trans

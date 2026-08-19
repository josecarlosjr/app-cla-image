"""Peça 2 — máquina de estados de bolha (Onda 13 Fase 3, research).

Orquestra a Peça 1 (GSADF calibrado: explosive? bsadf?) e a Peça 3
(reversão: entrada?) numa máquina de estados por ponto no tempo. Ponto
CENTRAL: BOLHA_ATIVA PERSISTE mesmo quando a Peça 1 adormece (o GSADF
apaga antes do topo) — só a Peça 3 a termina, E só quando o GSADF já
está MORTO (refinamento C, para bolhas de múltiplas pernas).

  Estados: CALMO, SUSPEITA, BOLHA_ATIVA, REVERSAO

  Transições:
    CALMO      → SUSPEITA:     Peça1 acende (explosive)
    SUSPEITA   → BOLHA_ATIVA:  Peça1 sustentada >= `sustain` janelas seguidas
    SUSPEITA   → CALMO:        Peça1 apaga antes de confirmar (falso alarme)
    BOLHA_ATIVA→ REVERSAO:     Peça3 dispara E o GSADF já está MORTO
                               (bsadf < 0 em >= `dead_windows` janelas) — C
    BOLHA_ATIVA (correção):    Peça3 dispara MAS o GSADF ainda tem vida
                               (bsadf >= 0 recente) → é correção de meio-ciclo,
                               MANTÉM BOLHA_ATIVA (não sai)
    BOLHA_ATIVA persiste:      mesmo com Peça1 apagada, até uma reversão real
    REVERSAO   → CALMO:        drawdown recupera < `rearm`

  A (re-entrada, rede de segurança): depois de REVERSAO→CALMO, o ciclo
  normal recomeça — se o GSADF reacende sustentado (>= `sustain`, o MESMO
  critério da entrada), CALMO→SUSPEITA→BOLHA_ATIVA reapanha uma 2ª perna.
  Não precisa de código próprio: é o fluxo normal a partir de CALMO.

Justificação C (principiada, NÃO afinada): uma queda com o GSADF ainda
vivo é correção dentro da bolha; o fim real vem com a exuberância morta
(bsadf claramente negativo, >= 2 janelas). Reusa "bsadf<0" (GSADF morto)
e ">= sustain janelas" (o critério da entrada) — sem parâmetros novos
escolhidos para acertar em 2021.

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
DEFAULT_DEAD_WINDOWS = 2  # janelas bsadf<0 consecutivas = GSADF morto (C)


def run_state_machine(
    dates: list,
    p1_explosive: list,
    p3_entry: list,
    drawdown: list,
    bsadf: list | None = None,
    *,
    sustain: int = DEFAULT_SUSTAIN,
    rearm: float = DEFAULT_REARM,
    dead_windows: int = DEFAULT_DEAD_WINDOWS,
) -> list[dict]:
    """Devolve [{ts, state, absorbed_correction}, ...] por ponto.

    ``bsadf[i]``: valor bsadf da Peça 1 nesse ponto (float|None). Necessário
    para o refinamento C. Se ``bsadf`` for None (série ausente), C fica
    desligado e a Peça3 termina a bolha incondicionalmente (comportamento
    antigo). ``absorbed_correction`` = True nos pontos onde a Peça3 disparou
    mas foi absorvida como correção (GSADF ainda vivo)."""
    n = len(dates)
    use_c = bsadf is not None
    if bsadf is None:
        bsadf = [None] * n
    if not (len(p1_explosive) == len(p3_entry) == len(drawdown)
            == len(bsadf) == n):
        raise ValueError("series desalinhadas")

    out: list[dict] = []
    state = CALMO
    consec = 0        # janelas Peça1 acesas consecutivas em SUSPEITA
    consec_dead = 0   # janelas bsadf<0 consecutivas (GSADF morto)

    for i in range(n):
        b = bsadf[i]
        if b is not None and b < 0:
            consec_dead += 1
        else:
            consec_dead = 0

        expl = bool(p1_explosive[i])
        entry = bool(p3_entry[i])
        dd = drawdown[i]
        absorbed = False

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
                gsadf_dead = (not use_c) or (consec_dead >= dead_windows)
                if gsadf_dead:
                    state = REVERSAO   # C: fim real (GSADF morto)
                else:
                    absorbed = True    # correção de meio-ciclo — mantém bolha

        elif state == REVERSAO:
            if dd is not None and dd < rearm:
                state = CALMO          # recuperou

        out.append({"ts": dates[i], "state": state,
                    "absorbed_correction": absorbed})
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


def absorbed_corrections(states: list[dict]) -> list:
    """Datas onde uma reversão da Peça3 foi absorvida como correção
    (mid-cycle, GSADF ainda vivo) sem sair de BOLHA_ATIVA."""
    return [r["ts"] for r in states if r.get("absorbed_correction")]

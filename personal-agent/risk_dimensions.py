"""The four risk dimensions, with explicit state and honest anchors.

The dashboard used to show danger only by omission: no badge meant
calm, but a reader could not tell "measured and fine" from "never
measured". These four always render, always with a state.

Each measures something the others do not:

    EXPLOSIVO   is the price rising faster than exponentially?
                BSADF explosive-root test, per ticker.
    VALUATION   is the price high against long-run earnings?
                Shiller CAPE, market-wide.
    CRÉDITO     is private credit above its long-run trend?
                BIS credit-to-GDP gap, per country (US here).
    STRESS      is the market already falling, and how unusually?
                Drawdown percentile vs the asset's own history,
                combined with the VIX.

STRESS deliberately replaces the old QUEDA and VOLATILIDADE badges:
those measured the same phenomenon by two routes and could disagree on
screen. Here the state is the WORSE of the two inputs, so a calm
drawdown with a panicking VIX still reads as danger.

ANCHORS — the point of this module
----------------------------------
Every threshold carries where it came from, and whether that is an
external anchor or our own design choice:

    anchor_kind "external"  a number someone else fixed and we adopted:
                            a null-distribution percentile, a Basel
                            trigger, the asset's own history.
    anchor_kind "design"    a number we picked because a middle band
                            was useful. Honest about being arbitrary.

The amber bands are mostly "design": there is no published authority
on where "attention" begins. Saying so in the tooltip is the whole
point — a threshold presented as principled when it is not is worse
than no threshold.

Pure functions: every input is already-fetched data, no DB, no network.
"""

CALM, WATCH, DANGER, UNKNOWN = "calm", "watch", "danger", "unknown"

_ORDER = {UNKNOWN: -1, CALM: 0, WATCH: 1, DANGER: 2}


def worst(*states: str) -> str:
    """The most severe of several states; UNKNOWN only if all are."""
    known = [s for s in states if s != UNKNOWN]
    if not known:
        return UNKNOWN
    return max(known, key=lambda s: _ORDER[s])


def _dim(key, label, state, value, display, measures,
         applied, anchor, anchor_kind, **extra) -> dict:
    return {
        "key": key,
        "label": label,
        "state": state,
        "value": value,
        "display": display,
        "measures": measures,
        "applied": applied,
        "anchor": anchor,
        "anchor_kind": anchor_kind,
        **extra,
    }


# ---------------------------------------------------------------------------
# EXPLOSIVO — BSADF, per ticker
# ---------------------------------------------------------------------------
# Thresholds come from bubble_scoring so the panel and the ensemble can
# never disagree about what "explosive" means.

def explosive_dimension(
    bsadf_recent: list[float] | None, crit95: float, min_consec: int,
) -> dict:
    """Amber on a single exceedance, red once it has persisted.

    The split is not decoration: measured daily BSADF moves are
    0.05–0.18 but spike past 2.0, so one crossing is inside the noise
    and two consecutive ones are not. Same rule the momentum signal
    scores on.
    """
    measures = (
        "Testa se o preço sobe de forma acelerada — raiz explosiva, "
        "não apenas uma subida (teste BSADF, Phillips-Shi-Yu 2015)."
    )
    anchor = (
        f"Limiar {crit95:.3f} = percentil 95 da distribuição nula, medido "
        "por Monte Carlo (30 000 caminhos aleatórios, n=250) contra o "
        "próprio estimador em uso, não copiado de tabela publicada."
    )
    if not bsadf_recent:
        return _dim("explosive", "EXPLOSIVO", UNKNOWN, None, "—", measures,
                    "Sem leitura do detetor para este ativo.",
                    anchor, "external", run=0)

    latest = bsadf_recent[-1]
    run = 0
    for v in reversed(bsadf_recent):
        if v is None or v <= crit95:
            break
        run += 1

    display = f"{latest:+.2f}"
    if run == 0:
        state, applied = CALM, (
            f"Atual {display}, abaixo do limiar {crit95:.3f}. "
            "Sem raiz explosiva."
        )
    elif run < min_consec:
        state, applied = WATCH, (
            f"Atual {display}, acima do limiar {crit95:.3f} mas só em "
            f"{run} observação. Uma travessia isolada ainda cabe no ruído "
            f"diário; são precisas {min_consec} consecutivas."
        )
    else:
        state, applied = DANGER, (
            f"Atual {display}, acima do limiar {crit95:.3f} em {run} "
            "observações consecutivas."
        )
    return _dim("explosive", "EXPLOSIVO", state, latest, display, measures,
                applied, anchor, "external", run=run)


# ---------------------------------------------------------------------------
# VALUATION — Shiller CAPE, market-wide
# ---------------------------------------------------------------------------

_CAPE_WATCH, _CAPE_DANGER = 22.0, 30.0


def valuation_dimension(cape: float | None) -> dict:
    measures = (
        "Preço face aos lucros reais médios de 10 anos (CAPE Shiller, "
        "S&P 500). Suaviza o ciclo de lucros, ao contrário do P/E."
    )
    anchor = (
        f"Limiar vermelho {_CAPE_DANGER:.0f} ≈ percentil 90 da história "
        "desde 1871; o pico da dotcom foi ~44 e o de 1929 ~33."
    )
    caveat = (
        f"A banda amarela ({_CAPE_WATCH:.0f}–{_CAPE_DANGER:.0f}) é escolha "
        "de desenho, não âncora externa: 22 é aproximadamente a média de "
        "longo prazo, e o intervalo até 30 é o 'acima da média mas longe "
        "do extremo'. Ninguém publicou este limiar."
    )
    if cape is None:
        return _dim("valuation", "VALUATION", UNKNOWN, None, "—", measures,
                    "Sem leitura do CAPE.", anchor, "external", caveat=caveat)
    display = f"{cape:.1f}"
    if cape < _CAPE_WATCH:
        state, applied = CALM, (
            f"Atual {display}, abaixo de {_CAPE_WATCH:.0f}.")
    elif cape < _CAPE_DANGER:
        state, applied = WATCH, (
            f"Atual {display}, entre {_CAPE_WATCH:.0f} e "
            f"{_CAPE_DANGER:.0f}.")
    else:
        state, applied = DANGER, (
            f"Atual {display}, acima de {_CAPE_DANGER:.0f}.")
    return _dim("valuation", "VALUATION", state, cape, display, measures,
                applied, anchor, "external", caveat=caveat)


# ---------------------------------------------------------------------------
# CRÉDITO — BIS credit-to-GDP gap
# ---------------------------------------------------------------------------

_CREDIT_WATCH, _CREDIT_DANGER = 0.0, 2.0


def credit_dimension(gap_pct: float | None, country: str = "US") -> dict:
    measures = (
        "Crédito ao setor privado face à sua tendência de longo prazo "
        "(gap credit-to-GDP do BIS). Mede EXCESSO, não nível."
    )
    anchor = (
        f"Limiar vermelho +{_CREDIT_DANGER:.0f}% = trigger do buffer "
        "contracíclico de capital, Basileia III — um número regulatório, "
        "não nosso."
    )
    caveat = (
        "Gaps muito negativos refletem desalavancagem e o endpoint bias "
        "do filtro HP; não medem segurança. BIS: trimestral, T+90."
    )
    if gap_pct is None:
        return _dim("credit", "CRÉDITO", UNKNOWN, None, "—", measures,
                    "Sem leitura do gap BIS.", anchor, "external",
                    caveat=caveat, country=country)
    display = f"{gap_pct:+.1f}%"
    if gap_pct < _CREDIT_WATCH:
        state, applied = CALM, (
            f"Atual {display} ({country}), abaixo da tendência.")
    elif gap_pct < _CREDIT_DANGER:
        state, applied = WATCH, (
            f"Atual {display} ({country}), acima da tendência mas abaixo "
            f"do trigger de +{_CREDIT_DANGER:.0f}%.")
    else:
        state, applied = DANGER, (
            f"Atual {display} ({country}), acima do trigger de "
            f"+{_CREDIT_DANGER:.0f}%.")
    return _dim("credit", "CRÉDITO", state, gap_pct, display, measures,
                applied, anchor, "external", caveat=caveat, country=country)


# ---------------------------------------------------------------------------
# STRESS — drawdown percentile + VIX, worst of the two
# ---------------------------------------------------------------------------

_STRESS_WATCH, _STRESS_DANGER = 80.0, 95.0
# Reuses pg_database._vix_status' own bands so two places cannot drift.
_VIX_STATE = {"calm": CALM, "nervous": WATCH,
              "fear": DANGER, "panic": DANGER, "unknown": UNKNOWN}


def stress_dimension(
    pct_rank: float | None,
    drawdown_pct: float | None,
    vix: float | None,
    vix_status: str | None,
    label_suffix: str = "",
) -> dict:
    """Worst of (drawdown percentile, VIX band).

    Self-calibrating by construction: the percentile is against the
    asset's OWN history, so -8% is routine for BTC and alarming for
    TLT without anyone choosing a per-asset threshold.
    """
    measures = (
        "Queda face ao pico dos últimos 90 dias, em percentil da própria "
        "história do ativo, combinada com o VIX. O estado é o PIOR dos "
        "dois."
    )
    anchor = (
        f"Limiar vermelho = percentil {_STRESS_DANGER:.0f} da história do "
        "próprio ativo (auto-calibrado, sem limiar fixo). VIX: bandas já "
        "usadas no dashboard (<15 calmo, <25 nervoso, <40 medo)."
    )
    caveat = (
        f"A banda amarela ({_STRESS_WATCH:.0f}–{_STRESS_DANGER:.0f}) é "
        "escolha de desenho. Nota: isto mede queda JÁ acontecida, não "
        "risco de queda futura — alto aqui costuma ser tarde."
    )

    dd_state = UNKNOWN
    if pct_rank is not None:
        dd_state = (CALM if pct_rank < _STRESS_WATCH
                    else WATCH if pct_rank < _STRESS_DANGER else DANGER)
    vix_state = _VIX_STATE.get(vix_status or "unknown", UNKNOWN)
    state = worst(dd_state, vix_state)

    parts = []
    if drawdown_pct is not None and pct_rank is not None:
        parts.append(f"queda {drawdown_pct:+.1f}% (percentil "
                     f"{pct_rank:.0f} da própria história)")
    if vix is not None:
        parts.append(f"VIX {vix:.1f}")
    applied = ("Atual: " + ", ".join(parts) + "."
               if parts else "Sem leitura de queda nem de VIX.")
    if state != UNKNOWN and dd_state != UNKNOWN and vix_state != UNKNOWN:
        driver = "queda" if _ORDER[dd_state] >= _ORDER[vix_state] else "VIX"
        applied += f" Estado determinado por: {driver}."

    display = (f"p{pct_rank:.0f}" if pct_rank is not None
               else (f"VIX {vix:.1f}" if vix is not None else "—"))
    return _dim("stress", "STRESS" + label_suffix, state, pct_rank, display,
                measures, applied, anchor, "external", caveat=caveat,
                drawdown_pct=drawdown_pct, vix=vix,
                drawdown_state=dd_state, vix_state=vix_state)


LEGEND = [
    {"key": "explosive", "label": "EXPLOSIVO",
     "short": "o preço acelera acima do que um passeio aleatório explica"},
    {"key": "valuation", "label": "VALUATION",
     "short": "preço alto face a 10 anos de lucros reais"},
    {"key": "credit", "label": "CRÉDITO",
     "short": "crédito privado acima da tendência de longo prazo"},
    {"key": "stress", "label": "STRESS",
     "short": "queda já em curso, face à história do próprio ativo"},
]

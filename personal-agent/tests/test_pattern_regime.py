"""Unit tests para pattern_matcher._maybe_compute_regime — helper que
compõe (regime_snapshot_json, regime_def_version) para anotar patterns
no momento da gravação.

Casos exigidos pelo checkpoint da Fase 2:
  - Input completo → snapshot serializado + REGIME_DEF_VERSION.
  - Input com stale → (None, None) + log estruturado.
  - Input com missing → (None, None) + log estruturado.

Extras baixo custo:
  - Row com ``no_data=True`` tratada como MISSING (não como stale).
  - ``mr.get_freshness`` a levantar excepção → (None, None) + error log,
    nunca propaga (não pode bloquear gravação do pattern).

Runnable both ways:
    pytest personal-agent/tests/test_pattern_regime.py
    python  personal-agent/tests/test_pattern_regime.py

Ficheiro separado de ``test_regime.py`` porque ``pattern_matcher`` puxa
importes pesados (feeds/llm/embeddings/database); ``test_regime.py``
mantém-se lean para o classificador puro.
"""
import json
import os
import sys
import tempfile
from unittest.mock import patch

# Bootstrap ANTES do import de pattern_matcher — pattern_matcher pega
# em database (SQLite em DATA_DIR) e telegram env.
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="test_pattern_regime_")
for _k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_ALLOWED_USER_ID",
           "ANTHROPIC_API_KEY", "VOYAGE_API_KEY", "FRED_API_KEY"):
    os.environ.pop(_k, None)

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import pattern_matcher  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers para construir freshness fixtures no mesmo shape de mr.get_freshness
# ---------------------------------------------------------------------------

def _row(indicator, value, *, is_stale=False, no_data=False):
    """Espelha o dict emitido por macro_repository.get_freshness."""
    cadence = "monthly" if indicator == "cape_shiller" else "daily"
    return {
        "indicator": indicator,
        "cadence": cadence,
        "latest_ts": None if no_data else "2026-06-26",
        "value": None if no_data else value,
        "no_data": no_data,
        "age_days": None if no_data else 1,
        "threshold_days": 40 if cadence == "monthly" else 6,
        "is_stale": bool(is_stale or no_data),
    }


def _all_fresh(vix=16.0, hy_oas=2.75, cape=41.66, tnx=4.48):
    """4 obrigatórios fresh + sp500 (que o helper ignora) para simular a
    lista real que mr.get_freshness devolve."""
    return [
        _row("vix", vix),
        _row("hy_oas", hy_oas),
        _row("cape_shiller", cape),
        _row("tnx_yield", tnx),
        _row("sp500_close", 7354.0),
    ]


# ---------------------------------------------------------------------------
# Testes
# ---------------------------------------------------------------------------

def test_complete_inputs_return_snapshot_and_version():
    """Todos os 4 fresh → snapshot serializado + REGIME_DEF_VERSION.
       Nenhum log de skip / erro."""
    with patch.object(pattern_matcher.mr, "get_freshness",
                      return_value=_all_fresh()), \
         patch.object(pattern_matcher, "log_event") as mock_log:
        snap_json, ver = pattern_matcher._maybe_compute_regime()

    assert snap_json is not None
    assert ver == pattern_matcher.REGIME_DEF_VERSION == 1

    snap = json.loads(snap_json)
    assert snap["def_version"] == 1
    assert snap["regimes"] == {
        "vix": "normal", "hy_oas": "apertado",
        "cape": "extremo", "erp": "comprimido",
    }, snap["regimes"]

    events = [c.args[0] for c in mock_log.call_args_list]
    assert "pattern_regime_skipped" not in events, events
    assert "pattern_regime_error" not in events, events


def test_stale_indicator_returns_null_pair_and_logs_skip():
    """CAPE stale → (None, None) + log com stale=['cape_shiller']."""
    rows = _all_fresh()
    for r in rows:
        if r["indicator"] == "cape_shiller":
            r["is_stale"] = True
            break

    with patch.object(pattern_matcher.mr, "get_freshness", return_value=rows), \
         patch.object(pattern_matcher, "log_event") as mock_log:
        snap_json, ver = pattern_matcher._maybe_compute_regime()

    assert snap_json is None and ver is None, (snap_json, ver)

    skips = [c for c in mock_log.call_args_list
             if c.args[0] == "pattern_regime_skipped"]
    assert len(skips) == 1, mock_log.call_args_list
    assert skips[0].kwargs.get("stale") == ["cape_shiller"], skips[0].kwargs
    assert skips[0].kwargs.get("missing") == [], skips[0].kwargs


def test_missing_indicator_returns_null_pair_and_logs_skip():
    """VIX ausente da lista → (None, None) + log com missing=['vix']."""
    rows = [r for r in _all_fresh() if r["indicator"] != "vix"]

    with patch.object(pattern_matcher.mr, "get_freshness", return_value=rows), \
         patch.object(pattern_matcher, "log_event") as mock_log:
        snap_json, ver = pattern_matcher._maybe_compute_regime()

    assert snap_json is None and ver is None

    skips = [c for c in mock_log.call_args_list
             if c.args[0] == "pattern_regime_skipped"]
    assert len(skips) == 1, mock_log.call_args_list
    assert skips[0].kwargs.get("missing") == ["vix"], skips[0].kwargs
    assert skips[0].kwargs.get("stale") == [], skips[0].kwargs


def test_no_data_row_treated_as_missing_not_stale():
    """Row com no_data=True conta como MISSING (não como stale).
       Diferença semântica: 'nunca houve observação' vs 'observação existe
       mas está velha'. O log deve reflectir isso."""
    rows = _all_fresh()
    for r in rows:
        if r["indicator"] == "hy_oas":
            r["no_data"] = True
            r["value"] = None
            r["is_stale"] = True  # get_freshness sempre marca stale se no_data
            break

    with patch.object(pattern_matcher.mr, "get_freshness", return_value=rows), \
         patch.object(pattern_matcher, "log_event") as mock_log:
        snap_json, ver = pattern_matcher._maybe_compute_regime()

    assert snap_json is None and ver is None

    skips = [c for c in mock_log.call_args_list
             if c.args[0] == "pattern_regime_skipped"]
    assert len(skips) == 1
    assert "hy_oas" in skips[0].kwargs.get("missing", []), skips[0].kwargs
    assert "hy_oas" not in skips[0].kwargs.get("stale", []), skips[0].kwargs


def test_get_freshness_raises_returns_null_pair_and_logs_error():
    """mr.get_freshness raises → (None, None) + log 'pattern_regime_error'
       com o motivo. NUNCA propaga excepção (senão bloqueava a gravação
       do pattern, contra o contrato 'honestidade > completude')."""
    with patch.object(pattern_matcher.mr, "get_freshness",
                      side_effect=RuntimeError("db offline")), \
         patch.object(pattern_matcher, "log_event") as mock_log:
        # Não deve levantar.
        snap_json, ver = pattern_matcher._maybe_compute_regime()

    assert snap_json is None and ver is None

    errors = [c for c in mock_log.call_args_list
              if c.args[0] == "pattern_regime_error"]
    assert len(errors) == 1
    assert errors[0].kwargs.get("reason") == "get_freshness_failed"


_TESTS = [
    ("test_complete_inputs_return_snapshot_and_version",
     test_complete_inputs_return_snapshot_and_version),
    ("test_stale_indicator_returns_null_pair_and_logs_skip",
     test_stale_indicator_returns_null_pair_and_logs_skip),
    ("test_missing_indicator_returns_null_pair_and_logs_skip",
     test_missing_indicator_returns_null_pair_and_logs_skip),
    ("test_no_data_row_treated_as_missing_not_stale",
     test_no_data_row_treated_as_missing_not_stale),
    ("test_get_freshness_raises_returns_null_pair_and_logs_error",
     test_get_freshness_raises_returns_null_pair_and_logs_error),
]


if __name__ == "__main__":
    for name, fn in _TESTS:
        try:
            fn()
            print(f"OK  {name}")
        except AssertionError as exc:
            print(f"FAIL {name}: {exc}")
            sys.exit(1)
    print(f"\nPASS  {len(_TESTS)}/{len(_TESTS)} pattern_matcher._maybe_compute_regime tests")

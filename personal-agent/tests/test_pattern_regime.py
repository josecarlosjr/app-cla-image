"""Unit tests para o gancho macro-regime de patterns.

Duas camadas:
  A. ``pattern_matcher._maybe_compute_regime`` — helper que compõe
     (regime_snapshot_json, regime_def_version) para anotar patterns
     no momento da gravação.
  B. ``GET /api/patterns/{id}/regime`` — endpoint que devolve o snapshot
     desserializado (envelope B2 ratificado no checkpoint da Fase 4).

Casos exigidos pelos checkpoints Fase 2 + Fase 4:
  A: completo → snap+ver; stale → NULL+NULL+log; missing → NULL+NULL+log.
  B: existente com snapshot → 200 + envelope; existente sem → 200 +
     regime_available=false + reason "not_computed_at_detection";
     inexistente → 404; snapshot corrupto → 200 + reason
     "snapshot_deserialization_failed" (defensivo).

Runnable both ways:
    pytest personal-agent/tests/test_pattern_regime.py
    python  personal-agent/tests/test_pattern_regime.py

Ficheiro separado de ``test_regime.py`` porque ``pattern_matcher`` +
``api`` puxam importes pesados (feeds/llm/embeddings/database/fastapi);
``test_regime.py`` mantém-se lean para o classificador puro.
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
import database as db   # noqa: E402
import api               # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


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


# ---------------------------------------------------------------------------
# B. GET /api/patterns/{pattern_id}/regime
# ---------------------------------------------------------------------------

_client: TestClient | None = None


def _api_client() -> TestClient:
    """Um TestClient partilhado — cheap para reutilizar entre testes."""
    global _client
    if _client is None:
        _client = TestClient(api.app)
    return _client


def _insert_test_pattern(*, snapshot_json=None, def_version=None,
                          confidence="MEDIA") -> int:
    """Grava um pattern mínimo e devolve o id gerado.

    Não usa mocks — vai mesmo ao SQLite temp para exercitar o path completo
    do endpoint (get_pattern_by_id → _row_to_pattern → JSON envelope).
    """
    db.insert_pattern(
        {
            "articles": [],
            "categories": ["test"],
            "sources": ["test-source"],
            "num_sources": 1,
            "analysis": "endpoint fixture",
            "confidence": confidence,
        },
        regime_snapshot_json=snapshot_json,
        regime_def_version=def_version,
    )
    row = db._db().execute(
        "SELECT MAX(id) AS id FROM patterns"
    ).fetchone()
    return int(row["id"])


def test_endpoint_pattern_with_snapshot_returns_envelope_and_snapshot():
    """Pattern com snapshot válido → 200, regime_available=true, snapshot
    desserializado com regimes={vix,hy_oas,cape,erp}."""
    snap = {
        "def_version": 1,
        "computed_at": "2026-07-08T14:00:00+00:00",
        "inputs": {"vix": 16.0, "hy_oas": 2.75, "cape": 41.66,
                   "ten_year": 4.48},
        "regimes": {"vix": "normal", "hy_oas": "apertado",
                    "cape": "extremo", "erp": "comprimido"},
        "derived": {"erp": -2.08},
    }
    pattern_id = _insert_test_pattern(
        snapshot_json=json.dumps(snap, ensure_ascii=False),
        def_version=1,
    )
    resp = _api_client().get(f"/api/patterns/{pattern_id}/regime")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["pattern_id"] == pattern_id
    assert body["regime_available"] is True
    assert body["snapshot"]["regimes"]["cape"] == "extremo"
    assert body["snapshot"]["regimes"]["erp"] == "comprimido"
    assert body["snapshot"]["def_version"] == 1


def test_endpoint_pattern_without_snapshot_returns_regime_unavailable():
    """Pattern com regime_snapshot_json NULL → 200, regime_available=false,
    reason=not_computed_at_detection."""
    pattern_id = _insert_test_pattern(snapshot_json=None, def_version=None)
    resp = _api_client().get(f"/api/patterns/{pattern_id}/regime")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {
        "pattern_id": pattern_id,
        "regime_available": False,
        "reason": "not_computed_at_detection",
    }


def test_endpoint_pattern_not_found_returns_404():
    """Id inexistente → 404 com envelope {'error': 'pattern not found'}.
    Escolho 99999 (garantido acima de qualquer id gerado nesta suite)."""
    resp = _api_client().get("/api/patterns/99999/regime")
    assert resp.status_code == 404, resp.text
    assert resp.json() == {"error": "pattern not found"}


def test_endpoint_snapshot_corrupt_json_returns_defensive_envelope():
    """regime_snapshot_json contém string não-JSON → 200 defensivo com
    reason=snapshot_deserialization_failed. Não pode explodir o endpoint
    por causa de 1 row corrupta (nunca deve acontecer, mas defesa em
    profundidade)."""
    pattern_id = _insert_test_pattern(
        snapshot_json="not-a-json-string {oops",
        def_version=1,  # def_version presente mas snap partido — edge caso.
    )
    with patch.object(api, "log_event") as mock_log:
        resp = _api_client().get(f"/api/patterns/{pattern_id}/regime")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["pattern_id"] == pattern_id
    assert body["regime_available"] is False
    assert body["reason"] == "snapshot_deserialization_failed"
    # Log estruturado para auditoria posterior — mesma prática que os
    # skips do helper.
    corrupt_events = [c for c in mock_log.call_args_list
                      if c.args[0] == "pattern_regime_endpoint_corrupt"]
    assert len(corrupt_events) == 1, mock_log.call_args_list
    assert corrupt_events[0].kwargs.get("pattern_id") == pattern_id


_TESTS = [
    # A. helper
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
    # B. endpoint
    ("test_endpoint_pattern_with_snapshot_returns_envelope_and_snapshot",
     test_endpoint_pattern_with_snapshot_returns_envelope_and_snapshot),
    ("test_endpoint_pattern_without_snapshot_returns_regime_unavailable",
     test_endpoint_pattern_without_snapshot_returns_regime_unavailable),
    ("test_endpoint_pattern_not_found_returns_404",
     test_endpoint_pattern_not_found_returns_404),
    ("test_endpoint_snapshot_corrupt_json_returns_defensive_envelope",
     test_endpoint_snapshot_corrupt_json_returns_defensive_envelope),
]


if __name__ == "__main__":
    for name, fn in _TESTS:
        try:
            fn()
            print(f"OK  {name}")
        except AssertionError as exc:
            print(f"FAIL {name}: {exc}")
            sys.exit(1)
    print(f"\nPASS  {len(_TESTS)}/{len(_TESTS)} pattern regime tests (helper + endpoint)")

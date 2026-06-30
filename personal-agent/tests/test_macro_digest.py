"""Smoke test for digest.py macro mode — pure builder + repo path.

Two layers:
  A. _format_macro_message: pure function, fixture dicts only.
  B. _gather_macro_data: temp SQLite seeded via mr.upsert_observations.

No Telegram send, no network, no LLM.

Runnable both ways:
    pytest personal-agent/tests/test_macro_digest.py
    python  personal-agent/tests/test_macro_digest.py
"""
import os
import sys
import tempfile
from datetime import datetime, timezone
from unittest.mock import patch

# Path bootstrap — set BEFORE importing the modules under test so
# DATA_DIR points at a throwaway SQLite, and so sibling imports
# (macro_repository, digest) resolve from personal-agent/.
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="macro_digest_")
# Block Telegram secrets so a stray HTTP call would fail loud, not silently.
os.environ.pop("TELEGRAM_BOT_TOKEN", None)
os.environ.pop("TELEGRAM_ALLOWED_USER_ID", None)

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import macro_repository as mr  # noqa: E402
import digest                   # noqa: E402


def _build(ind, cadence, recent, *, is_stale=False, age_days=0, no_data=False):
    """Compact constructor for one entry in `by_indicator`."""
    return {
        "freshness": {
            "indicator": ind, "cadence": cadence, "is_stale": is_stale,
            "age_days": age_days,
            "threshold_days": 6 if cadence == "daily" else 40,
            "no_data": no_data,
            "value": (recent[0]["value"] if recent else None),
            "latest_ts": (recent[0]["ts"] if recent else None),
        },
        "recent": recent,
    }


# ---------------------------------------------------------------------------
# A. Builder: pure-function fixtures
# ---------------------------------------------------------------------------

def test_a1_happy_path_matches_spec():
    """5 indicator lines exactly as the spec; no warnings; footer with date."""
    happy = {
        "fred_latest_ts": "2026-06-25",
        "by_indicator": {
            "vix":          _build("vix", "daily", [
                                {"ts": "2026-06-25", "value": 18.89},
                                {"ts": "2026-06-24", "value": 16.78}]),
            "hy_oas":       _build("hy_oas", "daily", [
                                {"ts": "2026-06-25", "value": 2.78},
                                {"ts": "2026-06-24", "value": 2.66}]),
            "sp500_close":  _build("sp500_close", "daily", [
                                {"ts": "2026-06-26", "value": 7354.02},
                                {"ts": "2026-06-25", "value": 7472.79}]),
            "tnx_yield":    _build("tnx_yield", "daily", [
                                {"ts": "2026-06-25", "value": 4.40},
                                {"ts": "2026-06-24", "value": 4.46}]),
            "cape_shiller": _build("cape_shiller", "monthly", [
                                {"ts": "2026-06-01", "value": 41.32},
                                {"ts": "2026-05-01", "value": 41.10}]),
        },
    }
    msg = digest._format_macro_message(happy)
    assert msg.startswith("*Macro - 25/06/2026*"), msg
    expected_lines = [
        "VIX: 18.89 (+2.11 vs 24/06)",
        "HY OAS: 2.78% (+0.12 vs 24/06)",
        "S&P 500: 7354.02 (-118.77 vs 25/06)",
        "10Y: 4.40% (-0.06 vs 24/06)",
        "CAPE: 41.32 (mensal, jun/2026)",
    ]
    for line in expected_lines:
        assert line in msg, f"missing line: {line!r}"
    assert "WARNING" not in msg
    assert "Dados FRED: fecho mais recente 25/06/2026; lag tipico 1-2 dias uteis" in msg


def test_a2_header_tracks_daily_cape_tracks_monthly():
    """Header date EXCLUDES CAPE — even if CAPE's ts is later, header tracks daily."""
    happy_by_ind = {
        "vix":          _build("vix", "daily", [
                            {"ts": "2026-06-25", "value": 18.89},
                            {"ts": "2026-06-24", "value": 16.78}]),
        "hy_oas":       _build("hy_oas", "daily", [
                            {"ts": "2026-06-25", "value": 2.78},
                            {"ts": "2026-06-24", "value": 2.66}]),
        "sp500_close":  _build("sp500_close", "daily", [
                            {"ts": "2026-06-26", "value": 7354.02},
                            {"ts": "2026-06-25", "value": 7472.79}]),
        "tnx_yield":    _build("tnx_yield", "daily", [
                            {"ts": "2026-06-25", "value": 4.40},
                            {"ts": "2026-06-24", "value": 4.46}]),
        "cape_shiller": _build("cape_shiller", "monthly",
                            [{"ts": "2026-08-01", "value": 42.0},
                             {"ts": "2026-07-01", "value": 41.7}]),
    }
    # fred_latest_ts is computed from daily only by _gather_macro_data; we set
    # it explicitly here to mimic that. The header MUST be 25/06, not 01/08.
    msg = digest._format_macro_message({
        "fred_latest_ts": "2026-06-25",
        "by_indicator": happy_by_ind,
    })
    assert msg.startswith("*Macro - 25/06/2026*")
    assert "(mensal, ago/2026)" in msg


def test_a3_stale_daily_single_warning_value_still_rendered():
    stale = {
        "fred_latest_ts": "2026-06-25",
        "by_indicator": {
            "hy_oas": _build("hy_oas", "daily", [
                          {"ts": "2026-06-12", "value": 3.85},
                          {"ts": "2026-06-11", "value": 3.80}],
                          is_stale=True, age_days=9),
            "vix": _build("vix", "daily", [
                        {"ts": "2026-06-25", "value": 18.89},
                        {"ts": "2026-06-24", "value": 16.78}]),
            "sp500_close": _build("sp500_close", "daily", [
                        {"ts": "2026-06-26", "value": 7354.02},
                        {"ts": "2026-06-25", "value": 7472.79}]),
            "tnx_yield": _build("tnx_yield", "daily", [
                        {"ts": "2026-06-25", "value": 4.40},
                        {"ts": "2026-06-24", "value": 4.46}]),
            "cape_shiller": _build("cape_shiller", "monthly", [
                        {"ts": "2026-06-01", "value": 41.32},
                        {"ts": "2026-05-01", "value": 41.10}]),
        },
    }
    msg = digest._format_macro_message(stale)
    assert "HY OAS: 3.85% (+0.05 vs 11/06)" in msg, msg
    assert "WARNING: HY OAS stale ha 9 dias uteis" in msg, msg
    assert msg.count("WARNING:") == 1, msg


def test_a4_monthly_stale_uses_calendar_days():
    """Monthly cadence: 'dias' (calendar), NOT 'dias uteis'."""
    stale_cape = {
        "fred_latest_ts": "2026-06-25",
        "by_indicator": {
            "vix": _build("vix", "daily", [
                        {"ts": "2026-06-25", "value": 18.89},
                        {"ts": "2026-06-24", "value": 16.78}]),
            "hy_oas": _build("hy_oas", "daily", [
                        {"ts": "2026-06-25", "value": 2.78},
                        {"ts": "2026-06-24", "value": 2.66}]),
            "sp500_close": _build("sp500_close", "daily", [
                        {"ts": "2026-06-26", "value": 7354.02},
                        {"ts": "2026-06-25", "value": 7472.79}]),
            "tnx_yield": _build("tnx_yield", "daily", [
                        {"ts": "2026-06-25", "value": 4.40},
                        {"ts": "2026-06-24", "value": 4.46}]),
            "cape_shiller": _build("cape_shiller", "monthly",
                        [{"ts": "2026-04-01", "value": 39.0},
                         {"ts": "2026-03-01", "value": 38.5}],
                        is_stale=True, age_days=85),
        },
    }
    msg = digest._format_macro_message(stale_cape)
    assert "WARNING: CAPE stale ha 85 dias" in msg
    assert "stale ha 85 dias uteis" not in msg


def test_a5_no_data_anywhere():
    empty = {
        "fred_latest_ts": None,
        "by_indicator": {
            ind: _build(ind, "daily" if ind != "cape_shiller" else "monthly",
                        recent=[], is_stale=True, no_data=True)
            for ind in digest._MACRO_ORDER
        },
    }
    msg = digest._format_macro_message(empty)
    assert msg.startswith("*Macro - sem dados*")
    assert "VIX: sem dados" in msg and "CAPE: sem dados" in msg
    assert msg.count("WARNING:") == 5
    assert "Dados FRED: sem observacoes recentes" in msg


def test_a6_single_obs_daily_no_prior_suffix():
    solo = {
        "fred_latest_ts": "2026-06-25",
        "by_indicator": {
            "vix": _build("vix", "daily",
                        [{"ts": "2026-06-25", "value": 18.89}]),
            "hy_oas": _build("hy_oas", "daily", [
                        {"ts": "2026-06-25", "value": 2.78},
                        {"ts": "2026-06-24", "value": 2.66}]),
            "sp500_close": _build("sp500_close", "daily", [
                        {"ts": "2026-06-26", "value": 7354.02},
                        {"ts": "2026-06-25", "value": 7472.79}]),
            "tnx_yield": _build("tnx_yield", "daily", [
                        {"ts": "2026-06-25", "value": 4.40},
                        {"ts": "2026-06-24", "value": 4.46}]),
            "cape_shiller": _build("cape_shiller", "monthly", [
                        {"ts": "2026-06-01", "value": 41.32},
                        {"ts": "2026-05-01", "value": 41.10}]),
        },
    }
    msg = digest._format_macro_message(solo)
    assert "VIX: 18.89 (sem observacao anterior)" in msg, msg


def test_a7_today_does_not_leak_into_header_or_footer():
    """Header AND footer must show max(daily_latest_ts), never today.

    Cenário: hoje é domingo 28/06/2026 (sem mercado), max(daily)=sexta
    26/06. O brief deve referir 26/06 em ambos os lados; nenhuma data
    de 27/06–30/06 pode aparecer.

    Defensive guard: hoje o formatter não chama ``datetime.now()``, mas
    se alguém um dia introduzir um "as of today" no header / footer e
    voltar atrás à hipótese errada de que ``today == max(daily)``,
    este teste falha imediatamente.
    """
    fri = "2026-06-26"
    thu = "2026-06-25"
    fixture = {
        "fred_latest_ts": fri,
        "by_indicator": {
            "vix":          _build("vix", "daily",
                            [{"ts": fri, "value": 18.89},
                             {"ts": thu, "value": 16.78}]),
            "hy_oas":       _build("hy_oas", "daily",
                            [{"ts": fri, "value": 2.78},
                             {"ts": thu, "value": 2.66}]),
            "sp500_close":  _build("sp500_close", "daily",
                            [{"ts": fri, "value": 7354.02},
                             {"ts": thu, "value": 7472.79}]),
            "tnx_yield":    _build("tnx_yield", "daily",
                            [{"ts": fri, "value": 4.40},
                             {"ts": thu, "value": 4.46}]),
            "cape_shiller": _build("cape_shiller", "monthly",
                            [{"ts": "2026-06-01", "value": 41.32},
                             {"ts": "2026-05-01", "value": 41.10}]),
        },
    }
    # `digest.datetime` é o símbolo `datetime` re-exportado por
    # `from datetime import datetime, ...`. Patchar aqui apanha
    # qualquer futura chamada `datetime.now()` dentro do formatter.
    sunday = datetime(2026, 6, 28, 10, 0, 0, tzinfo=timezone.utc)
    with patch.object(digest, "datetime") as mock_dt:
        mock_dt.now.return_value = sunday
        mock_dt.fromisoformat = datetime.fromisoformat  # preservar parsing
        msg = digest._format_macro_message(fixture)

    assert msg.startswith("*Macro - 26/06/2026*"), msg[:60]
    assert "Dados FRED: fecho mais recente 26/06/2026" in msg, msg
    # Nenhuma data de hoje / weekend pode aparecer no brief.
    for forbidden in ("27/06", "28/06", "29/06", "30/06"):
        assert forbidden not in msg, (
            f"data {forbidden!r} (today/weekend) vazou no brief:\n{msg}"
        )


# ---------------------------------------------------------------------------
# B. Repo path: _gather_macro_data hits real SQLite via macro_repository
# ---------------------------------------------------------------------------

def _seed_db():
    mr.upsert_observations("vix", [
        {"ts": "2026-06-24", "value": 16.78, "metadata": {"x": 1}},
        {"ts": "2026-06-25", "value": 18.89, "metadata": {"x": 1}}])
    mr.upsert_observations("hy_oas", [
        {"ts": "2026-06-24", "value": 2.66, "metadata": {"x": 1}},
        {"ts": "2026-06-25", "value": 2.78, "metadata": {"x": 1}}])
    mr.upsert_observations("sp500_close", [
        {"ts": "2026-06-25", "value": 7472.79, "metadata": {"x": 1}},
        {"ts": "2026-06-26", "value": 7354.02, "metadata": {"x": 1}}])
    mr.upsert_observations("tnx_yield", [
        {"ts": "2026-06-24", "value": 4.46, "metadata": {"x": 1}},
        {"ts": "2026-06-25", "value": 4.40, "metadata": {"x": 1}}])
    mr.upsert_observations("cape_shiller", [
        {"ts": "2026-05-01", "value": 41.10, "metadata": {"x": 1}},
        {"ts": "2026-06-01", "value": 41.32, "metadata": {"x": 1}}])


def test_b1_gather_macro_data_from_sqlite():
    _seed_db()
    data = digest._gather_macro_data()
    # fred_latest_ts = max daily = 2026-06-26 (sp500)
    assert data["fred_latest_ts"] == "2026-06-26", data["fred_latest_ts"]
    vix_recent = data["by_indicator"]["vix"]["recent"]
    assert [r["ts"] for r in vix_recent] == ["2026-06-25", "2026-06-24"]
    assert [r["value"] for r in vix_recent] == [18.89, 16.78]
    cape_recent = data["by_indicator"]["cape_shiller"]["recent"]
    assert [r["ts"] for r in cape_recent] == ["2026-06-01", "2026-05-01"]


def test_b2_real_db_render_end_to_end():
    _seed_db()
    data = digest._gather_macro_data()
    msg_real = digest._format_macro_message(data)
    assert "S&P 500: 7354.02 (-118.77 vs 25/06)" in msg_real, msg_real
    assert msg_real.startswith("*Macro - 26/06/2026*"), msg_real[:60]


if __name__ == "__main__":
    # Standalone runner — the cluster image doesn't ship pytest.
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"OK  {fn.__name__}")
    print(f"\nPASS  {len(tests)}/{len(tests)} digest.py macro mode tests")

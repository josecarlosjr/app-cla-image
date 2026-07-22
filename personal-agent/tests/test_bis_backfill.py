"""Unit tests for ``jobs.bis_backfill`` — one-shot BIS backfill.

Cobertura pedida no brief da Fase 2(c):
  - Idempotência: 2× run → 0 inserts, 0 updates na 2ª (via
    ``update_on_change`` no catálogo — prova obrigatória).
  - Partial failure → exit 1 mas os ok persistem.
  - Preflight mostra rows existentes.
  - Summary totals agregam correctamente.

Extras baixo custo:
  - Zero import de ``macro_backfill`` (invariante das camadas).

Runnable both ways:
    pytest personal-agent/tests/test_bis_backfill.py
    python  personal-agent/tests/test_bis_backfill.py
"""
import asyncio
import inspect
import io
import os
import sys
import tempfile
from unittest.mock import patch

# Bootstrap ANTES de importar bis_backfill/bis_fetcher — macro_repository
# puxa database, que precisa de DATA_DIR configurado num tmp.
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="test_bis_backfill_")
for _k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_ALLOWED_USER_ID",
           "ANTHROPIC_API_KEY", "VOYAGE_API_KEY", "FRED_API_KEY"):
    os.environ.pop(_k, None)

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import macro_repository as mr           # noqa: E402
from jobs import bis_fetcher, bis_backfill  # noqa: E402

# Elimina o sleep de preflight globalmente para todos os testes deste ficheiro.
bis_backfill.WARM_UP_S = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, csv_text: str, status_code: int = 200,
                 content_type: str = "application/vnd.sdmx.data+csv"):
        self.text = csv_text
        self.status_code = status_code
        self.headers = {"content-type": content_type}


class _FakeClient:
    """Mock httpx.AsyncClient com per-URL response mapping.

    ``url_patterns`` é lista de ``(substring, response)`` — primeira
    substring encontrada na URL determina a resposta. Se nenhuma casar,
    devolve ``default``.
    Também suporta ``async with`` para bater com o uso do fetcher.
    """
    def __init__(self, default: _FakeResponse,
                 url_patterns: list | None = None):
        self.default = default
        self.url_patterns = url_patterns or []
        self.requested_urls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None

    async def get(self, url, params=None, headers=None, timeout=None):
        self.requested_urls.append(url)
        for pattern, resp in self.url_patterns:
            if pattern in url:
                return resp
        return self.default


def _clean_bis_rows():
    """Limpa todas as rows bis_* de macro_indicators. Chamado no início
    de cada test que toca DB — evita cross-contamination entre tests."""
    conn = mr._db()
    with conn:
        conn.execute(
            "DELETE FROM macro_indicators WHERE indicator LIKE 'bis_%'"
        )


def _count_bis_rows() -> int:
    conn = mr._db()
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM macro_indicators "
        "WHERE indicator LIKE 'bis_%'"
    ).fetchone()
    return row["n"]


def _patch_httpx(fake_client: _FakeClient):
    """Context manager que patcha bis_fetcher.httpx.AsyncClient para
    devolver o fake_client. Reutilizado por vários tests."""
    return patch.object(
        bis_fetcher.httpx, "AsyncClient", return_value=fake_client,
    )


_DEFAULT_CSV = (
    "TIME_PERIOD:Time period,OBS_VALUE:Observation value\n"
    "2020-Q1,3.5\n"
    "2020-Q2,4.1\n"
    "2020-Q3,5.2\n"
)


# ---------------------------------------------------------------------------
# 1. Idempotência (prova obrigatória do brief)
# ---------------------------------------------------------------------------

def test_backfill_idempotency_second_run_zero_writes():
    """Run 1: N rows persistidas nos 28 indicadores (3 obs cada = 84 rows).
       Run 2: mesmo CSV → 0 inserts + 0 updates (update_on_change semantica
       garante que valores iguais não geram write). DB row count fica igual."""
    _clean_bis_rows()
    fake_client_1 = _FakeClient(default=_FakeResponse(_DEFAULT_CSV))
    with _patch_httpx(fake_client_1):
        exit_1 = bis_backfill.main([], stream=io.StringIO())
    assert exit_1 == 0, "run 1 must succeed"

    rows_after_1 = _count_bis_rows()
    # 28 indicadores × 3 obs = 84
    assert rows_after_1 == 84, f"expected 84 rows after run 1, got {rows_after_1}"

    # Run 2: capturar log_event para verificar totals=0
    fake_client_2 = _FakeClient(default=_FakeResponse(_DEFAULT_CSV))
    captured: list[tuple] = []

    def _capture(event, **kw):
        captured.append((event, kw))

    with _patch_httpx(fake_client_2), \
         patch.object(bis_backfill, "log_event", _capture):
        exit_2 = bis_backfill.main([], stream=io.StringIO())

    assert exit_2 == 0, "run 2 must succeed"

    rows_after_2 = _count_bis_rows()
    assert rows_after_2 == rows_after_1, (
        f"idempotency broken: {rows_after_1} → {rows_after_2}"
    )

    summaries = [kw for ev, kw in captured if ev == "bis_backfill_summary"]
    assert len(summaries) == 1, captured
    s = summaries[0]
    assert s["total_inserted"] == 0, s
    assert s["total_updated"] == 0, s
    assert s["n_ok"] == 28, s
    assert s["n_error"] == 0, s


# ---------------------------------------------------------------------------
# 2. Partial failure → exit 1
# ---------------------------------------------------------------------------

def test_backfill_partial_failure_returns_exit_1():
    """2 indicadores devolvem HTTP 500, os outros 26 retornam CSV OK.
       Exit code = 1; os 26 rows persistem; os 2 têm log_event bis_fetch_error."""
    _clean_bis_rows()
    err_resp = _FakeResponse(
        "Internal Server Error", status_code=500, content_type="text/plain",
    )
    # Match apenas gap Q.CN.P.A.C e Q.BR.P.A.C (2 indicadores exactos)
    fake = _FakeClient(
        default=_FakeResponse(_DEFAULT_CSV),
        url_patterns=[
            ("Q.CN.P.A.C", err_resp),
            ("Q.BR.P.A.C", err_resp),
        ],
    )

    captured: list[tuple] = []
    def _capture(event, **kw):
        captured.append((event, kw))

    with _patch_httpx(fake), \
         patch.object(bis_backfill, "log_event", _capture), \
         patch.object(bis_fetcher, "log_event", _capture):
        exit_code = bis_backfill.main([], stream=io.StringIO())

    assert exit_code == 1

    # Summary correcto
    summaries = [kw for ev, kw in captured if ev == "bis_backfill_summary"]
    assert len(summaries) == 1
    s = summaries[0]
    assert s["n_ok"] == 26, s
    assert s["n_error"] == 2, s

    # 2 log_events de erro (um por indicador que falhou)
    errors = [kw for ev, kw in captured if ev == "bis_fetch_error"]
    assert len(errors) == 2, errors
    failed_ids = {e["indicator"] for e in errors}
    assert failed_ids == {"bis_credit_gap_cn", "bis_credit_gap_br"}, failed_ids

    # 26 × 3 obs = 78 rows persistem
    assert _count_bis_rows() == 78, _count_bis_rows()


# ---------------------------------------------------------------------------
# 3. Preflight mostra rows existentes
# ---------------------------------------------------------------------------

def test_backfill_preflight_shows_existing_rows():
    """Seed DB com 5 rows para bis_credit_gap_pt. Preflight imprime a
    contagem e devolve dict de counts com o valor correcto. Zero rows
    são adicionadas por preflight — apenas leitura."""
    _clean_bis_rows()
    # Seed via upsert directo
    rows = [
        {"ts": f"202{i}-03-31T00:00:00+00:00",
         "value": 3.5 + i,
         "metadata": {"source": "bis", "test": True}}
        for i in range(5)
    ]
    mr.upsert_observations("bis_credit_gap_pt", rows)

    buf = io.StringIO()
    counts = bis_backfill._preflight(stream=buf)

    output = buf.getvalue()
    # Contagem no dict devolvido
    assert counts["bis_credit_gap_pt"] == 5, counts["bis_credit_gap_pt"]
    # Contagem no output
    assert "bis_credit_gap_pt" in output
    assert "5 rows" in output, output
    # Aviso de idempotência aparece porque total_existing > 0
    assert "Idempotent" in output
    # Outros indicadores aparecem com 0 rows
    assert "bis_credit_gap_us" in output
    assert counts["bis_credit_gap_us"] == 0


# ---------------------------------------------------------------------------
# 4. Summary totals correctos
# ---------------------------------------------------------------------------

def test_backfill_summary_totals_aggregate_correctly():
    """3 indicadores 'reportam' 10/20/30 rows inserted; os outros 25 → 0.
       Summary emit deve mostrar total_inserted == 60. Isola aggregation
       logic patchando fetch_one — evita ir ao HTTP + parse + upsert."""
    _clean_bis_rows()
    n_map = {
        "bis_credit_gap_us": 10,
        "bis_credit_gap_pt": 20,
        "bis_credit_gap_jp": 30,
    }

    async def _controlled_fetch(client, ind_id, *, start_period=None):
        n = n_map.get(ind_id, 0)
        return {
            "indicator": ind_id, "ok": True,
            "n_obs": n, "n_inserted": n, "n_updated": 0,
            "error": None,
        }

    captured: list[tuple] = []
    def _capture(event, **kw):
        captured.append((event, kw))

    # httpx.AsyncClient() é instanciado mesmo com fetch_one patchado,
    # mas o client nunca é usado — patchar por segurança.
    fake_client = _FakeClient(default=_FakeResponse(_DEFAULT_CSV))
    with _patch_httpx(fake_client), \
         patch.object(bis_fetcher, "fetch_one", _controlled_fetch), \
         patch.object(bis_backfill, "log_event", _capture):
        exit_code = bis_backfill.main([], stream=io.StringIO())

    assert exit_code == 0

    summaries = [kw for ev, kw in captured if ev == "bis_backfill_summary"]
    assert len(summaries) == 1
    s = summaries[0]
    assert s["total_inserted"] == 60, s
    assert s["total_updated"] == 0, s
    assert s["n_ok"] == 28, s
    assert s["n_error"] == 0, s


# ---------------------------------------------------------------------------
# 5. Start-period CLI arg é propagado
# ---------------------------------------------------------------------------

def test_backfill_start_period_arg_reaches_fetcher():
    """--start-period 2000 chega ao bis_fetcher.run() via kwarg. Verifica
    via patch de bis_fetcher.run para capturar o argumento."""
    _clean_bis_rows()

    captured_kwargs = {}

    async def _spy_run(*, start_period=None):
        captured_kwargs["start_period"] = start_period
        return 28, 0, [
            {"indicator": ind, "ok": True, "n_obs": 0,
             "n_inserted": 0, "n_updated": 0, "error": None}
            for ind in bis_fetcher.SUPPORTED_INDICATORS
        ]

    with patch.object(bis_fetcher, "run", _spy_run):
        exit_code = bis_backfill.main(
            ["--start-period", "2000"], stream=io.StringIO(),
        )

    assert exit_code == 0
    assert captured_kwargs["start_period"] == "2000"


# ---------------------------------------------------------------------------
# 6. Zero import de macro_backfill (invariante das camadas)
# ---------------------------------------------------------------------------

def test_bis_backfill_does_not_import_macro_backfill():
    """As duas backfills (macro-FRED e BIS) coabitam independentemente,
    mesmo princípio das camadas ratificado em Fase 1B.

    Testa apenas padrões de USO de código:
      - ``import macro_backfill`` / ``from macro_backfill``
      - ``macro_backfill.<attr>`` (attribute access)
    Menções na prosa (docstring / comentários) são aceitáveis — servem
    de contexto humano."""
    src = inspect.getsource(bis_backfill)
    assert "import macro_backfill" not in src, "bis_backfill imports macro_backfill"
    assert "from macro_backfill" not in src, "bis_backfill imports from macro_backfill"
    assert "macro_backfill." not in src, (
        "bis_backfill accesses macro_backfill.<attr> (should be independent)"
    )


_TESTS = [
    ("test_backfill_idempotency_second_run_zero_writes",
     test_backfill_idempotency_second_run_zero_writes),
    ("test_backfill_partial_failure_returns_exit_1",
     test_backfill_partial_failure_returns_exit_1),
    ("test_backfill_preflight_shows_existing_rows",
     test_backfill_preflight_shows_existing_rows),
    ("test_backfill_summary_totals_aggregate_correctly",
     test_backfill_summary_totals_aggregate_correctly),
    ("test_backfill_start_period_arg_reaches_fetcher",
     test_backfill_start_period_arg_reaches_fetcher),
    ("test_bis_backfill_does_not_import_macro_backfill",
     test_bis_backfill_does_not_import_macro_backfill),
]


if __name__ == "__main__":
    for name, fn in _TESTS:
        try:
            fn()
            print(f"OK  {name}")
        except AssertionError as exc:
            print(f"FAIL {name}: {exc}")
            sys.exit(1)
    print(f"\nPASS  {len(_TESTS)}/{len(_TESTS)} bis_backfill tests")

"""Unit tests for ``jobs.bis_fetcher`` — BIS credit-to-GDP async fetcher.

Cobertura pedida no brief da Fase 2(b):
  - Regex guard narrow gap / ratio (dim[3] == 'A' preservado)
  - Country codes uppercase ISO 3166-1 alpha-2
  - ``_bis_period_to_iso`` — quarterly + annual + inválidos
  - Missing markers filtrados
  - HTML response → bot-wall
  - CSV real parseia para observações

Extras baixo custo:
  - Zero import de ``quant_bis`` (invariante ratificada em Fase 1B)
  - Dry-run end-to-end com httpx mocked — prova que ``fetch_one``
    upserta correctamente ao SQLite via ``macro_repository``

Runnable both ways:
    pytest personal-agent/tests/test_bis_fetcher.py
    python  personal-agent/tests/test_bis_fetcher.py
"""
import asyncio
import inspect
import os
import re
import sys
import tempfile

# Bootstrap ANTES de importar bis_fetcher — macro_repository puxa
# database, que precisa de DATA_DIR configurado num tmp.
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="test_bis_fetcher_")
for _k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_ALLOWED_USER_ID",
           "ANTHROPIC_API_KEY", "VOYAGE_API_KEY", "FRED_API_KEY"):
    os.environ.pop(_k, None)

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import macro_repository as mr        # noqa: E402
from jobs import bis_fetcher          # noqa: E402


# ---------------------------------------------------------------------------
# 1. Regex guard — os 28 series_keys casam narrow gap / ratio
# ---------------------------------------------------------------------------

def test_narrow_gap_series_key_regex_covers_all_28():
    """Cada BIS entry no catálogo tem series_key matching
    ``^Q\\.[A-Z]{2}\\.P\\.A\\.[AC]$`` — 'A' na quarta dim garante que
    é total credit (Basel III narrow), não bank-only."""
    pat = re.compile(r"^Q\.[A-Z]{2}\.P\.A\.[AC]$")
    bad: list[str] = []
    for ind in bis_fetcher.SUPPORTED_INDICATORS:
        sk = mr.INDICATORS[ind]["series_key"]
        if not pat.match(sk):
            bad.append(f"{ind}: {sk}")
    assert not bad, f"BIS series_keys off narrow-or-ratio: {bad}"
    assert len(bis_fetcher.SUPPORTED_INDICATORS) == 28


# ---------------------------------------------------------------------------
# 2. Country codes uppercase ISO 3166-1 alpha-2
# ---------------------------------------------------------------------------

def test_country_codes_are_uppercase_iso2():
    """BIS API espera ISO alpha-2 uppercase (GB, PT, DE, ...). Detecta
    typos tipo 'Us' (mixed case), 'USA' (alpha-3), 'p' (1 char), etc."""
    bad: list[str] = []
    for ind in bis_fetcher.SUPPORTED_INDICATORS:
        c = mr.INDICATORS[ind]["country"]
        if not (len(c) == 2 and c.isalpha() and c.isupper()):
            bad.append(f"{ind}: {c!r}")
    assert not bad, f"country codes off ISO2-upper: {bad}"


# ---------------------------------------------------------------------------
# 3. Period → ISO conversion
# ---------------------------------------------------------------------------

def test_period_to_iso_quarterly_all_four():
    """Todos os quatro quarters mapeiam ao último dia do trimestre."""
    assert bis_fetcher._bis_period_to_iso("2026-Q1") == "2026-03-31T00:00:00+00:00"
    assert bis_fetcher._bis_period_to_iso("2026-Q2") == "2026-06-30T00:00:00+00:00"
    assert bis_fetcher._bis_period_to_iso("2026-Q3") == "2026-09-30T00:00:00+00:00"
    assert bis_fetcher._bis_period_to_iso("2026-Q4") == "2026-12-31T00:00:00+00:00"


def test_period_to_iso_compact_and_annual_and_invalid():
    """Forma compacta ``YYYYQn`` também aceite; fallback anual
    ``YYYY`` → 31-Dec; strings inválidas → None."""
    # Forma compacta
    assert bis_fetcher._bis_period_to_iso("1980Q1") == "1980-03-31T00:00:00+00:00"
    # Case-insensitive
    assert bis_fetcher._bis_period_to_iso("1980-q1") == "1980-03-31T00:00:00+00:00"
    # Fallback anual
    assert bis_fetcher._bis_period_to_iso("2023") == "2023-12-31T00:00:00+00:00"
    # Inválidos → None
    for bad in ("", "  ", "garbage", "2026-Q5", "2026-Q0", "26Q1",
                "2026-M03", "not-a-date"):
        assert bis_fetcher._bis_period_to_iso(bad) is None, bad


# ---------------------------------------------------------------------------
# 4. Missing markers filtered by parser
# ---------------------------------------------------------------------------

def test_missing_markers_all_variants_filtered():
    """Os 5 markers observados em BIS SDMX-CSV, mais variantes de case,
    são silenciosamente droppados. Só os dois valores válidos passam."""
    csv_text = (
        "TIME_PERIOD:Time period,OBS_VALUE:Observation value\n"
        "2020-Q1,12.5\n"
        "2020-Q2,\n"       # empty string
        "2020-Q3,NaN\n"    # NaN
        "2020-Q4,nan\n"    # nan lowercase
        "2021-Q1,NA\n"     # NA
        "2021-Q2,na\n"     # na lowercase
        "2021-Q3,.\n"      # dot
        "2021-Q4,n/a\n"    # n/a
        "2022-Q1,N/A\n"    # N/A
        "2022-Q2,15.2\n"
    )
    obs = bis_fetcher._bis_parse_sdmx_csv(csv_text)
    assert obs == [
        ("2020-03-31T00:00:00+00:00", 12.5),
        ("2022-06-30T00:00:00+00:00", 15.2),
    ], obs


def test_non_numeric_value_dropped_silently():
    """Valores não-numéricos fora dos markers reconhecidos (``abc``,
    ``NULL``, ``12.5x``) são silenciosamente droppados. Defesa contra
    CSV malformado upstream. NB: ``"12,5"`` não é testável aqui — a
    vírgula é o delimitador CSV, o parser splittá-a como 2 células."""
    csv_text = (
        "TIME_PERIOD,OBS_VALUE\n"
        "2020-Q1,3.5\n"
        "2020-Q2,abc\n"      # letras puras
        "2020-Q3,NULL\n"     # não é marker reconhecido; não é numérico
        "2020-Q4,12.5x\n"    # numérico com sufixo — float() rejeita
        "2021-Q1,4.1\n"
    )
    obs = bis_fetcher._bis_parse_sdmx_csv(csv_text)
    assert obs == [
        ("2020-03-31T00:00:00+00:00", 3.5),
        ("2021-03-31T00:00:00+00:00", 4.1),
    ], obs


# ---------------------------------------------------------------------------
# 5. HTML / bot-wall detection
# ---------------------------------------------------------------------------

def test_html_response_detected_as_botwall_by_content_type():
    class R:
        headers = {"content-type": "text/html; charset=utf-8"}
    assert bis_fetcher._is_botwall("<!DOCTYPE html>...", R()) is True


def test_html_response_detected_as_botwall_by_leading_bracket():
    """Content-type engana (às vezes BIS devolve HTML com Content-Type
    ambíguo); o segundo guard verifica o body começa com '<'."""
    class R:
        headers = {"content-type": "text/csv"}
    assert bis_fetcher._is_botwall("<html>...", R()) is True


def test_valid_csv_is_not_botwall():
    """CSV genuíno passa o guard."""
    class R:
        headers = {"content-type": "application/vnd.sdmx.data+csv"}
    body = "TIME_PERIOD,OBS_VALUE\n2020-Q1,12.5\n"
    assert bis_fetcher._is_botwall(body, R()) is False


# ---------------------------------------------------------------------------
# 6. Realistic CSV parses to observations
# ---------------------------------------------------------------------------

def test_valid_csv_parses_to_observations():
    """CSV com o layout completo que BIS emite (várias dimensões +
    metadata) — o parser localiza TIME_PERIOD e OBS_VALUE por fragment
    match e ignora as restantes."""
    csv_text = (
        "DATAFLOW,FREQ,BORROWERS_CTY,TC_BORROWERS,TC_LENDERS,CG_DTYPE,"
        "TIME_PERIOD:Time period,OBS_VALUE:Observation value,"
        "UNIT_MEASURE\n"
        "BIS:WS_CREDIT_GAP(1.0),Q,PT,P,A,C,2010-Q1,3.5,PT\n"
        "BIS:WS_CREDIT_GAP(1.0),Q,PT,P,A,C,2010-Q2,4.1,PT\n"
        "BIS:WS_CREDIT_GAP(1.0),Q,PT,P,A,C,2011-Q4,12.8,PT\n"
    )
    obs = bis_fetcher._bis_parse_sdmx_csv(csv_text)
    assert obs == [
        ("2010-03-31T00:00:00+00:00", 3.5),
        ("2010-06-30T00:00:00+00:00", 4.1),
        ("2011-12-31T00:00:00+00:00", 12.8),
    ]


# ---------------------------------------------------------------------------
# 7. Zero import of quant_bis (invariante ratificada em Fase 1B)
# ---------------------------------------------------------------------------

def test_no_import_of_quant_bis():
    """As duas camadas (macro / quant) ficam independentes. Detecta
    regressão futura em que alguém queira DRY-ar via import."""
    src = inspect.getsource(bis_fetcher)
    assert "import quant_bis" not in src, "bis_fetcher imports quant_bis"
    assert "from quant_bis" not in src, "bis_fetcher imports from quant_bis"


def test_macro_fetcher_does_not_import_bis_fetcher():
    """Invariante bidireccional: ``macro_fetcher`` (Camada A FRED/Shiller)
    também não conhece ``bis_fetcher``. Se um dia alguém quiser unificar
    o run_all para cobrir também BIS, este teste apanha a mudança e
    força discussão explícita da arquitectura em vez de acoplar por
    inércia.

    Padrão de detecção espelha o test 6 de ``test_bis_backfill.py``:
    procura ``import bis_fetcher``, ``from bis_fetcher``, ou
    ``bis_fetcher.<attr>`` (uso em código). Menções em docstring /
    comentários são aceitáveis — servem de contexto humano."""
    from jobs import macro_fetcher
    src = inspect.getsource(macro_fetcher)
    assert "import bis_fetcher" not in src, (
        "macro_fetcher imports bis_fetcher"
    )
    assert "from bis_fetcher" not in src, (
        "macro_fetcher imports from bis_fetcher"
    )
    assert "bis_fetcher." not in src, (
        "macro_fetcher accesses bis_fetcher.<attr> (should be independent)"
    )


# ---------------------------------------------------------------------------
# 8. Dry-run end-to-end com httpx mocked
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, csv_text: str, status_code: int = 200,
                 content_type: str = "application/vnd.sdmx.data+csv"):
        self.text = csv_text
        self.status_code = status_code
        self.headers = {"content-type": content_type}


class _FakeClient:
    """Mock mínimo do httpx.AsyncClient para bis_fetcher.fetch_one.
    Devolve sempre a resposta configurada — não simula rede real, prova
    apenas o wiring: HTTP → parse → upsert → DB."""
    def __init__(self, response: _FakeResponse):
        self.response = response
        self.requests: list[str] = []

    async def get(self, url, params=None, headers=None, timeout=None):
        self.requests.append(url)
        return self.response


def test_fetch_one_end_to_end_upserts_to_sqlite():
    """Full path: mocked HTTP devolve CSV válido para PT gap → fetch_one
    parseia + upserta ao SQLite temp → macro_repository.get_recent
    confirma as 2 rows persistidas."""
    csv_text = (
        "TIME_PERIOD:Time period,OBS_VALUE:Observation value\n"
        "2010-Q1,3.5\n"
        "2011-Q4,12.8\n"
    )
    client = _FakeClient(_FakeResponse(csv_text))

    async def _drive():
        return await bis_fetcher.fetch_one(client, "bis_credit_gap_pt")

    result = asyncio.run(_drive())
    assert result["ok"] is True, result
    assert result["error"] is None, result
    assert result["n_obs"] == 2
    assert result["n_inserted"] == 2, result
    # Sanity do URL construído — inclui dataflow, series_key, format, startPeriod
    assert len(client.requests) == 1
    req_url = client.requests[0]
    assert "BIS,WS_CREDIT_GAP,1.0" in req_url
    assert "Q.PT.P.A.C" in req_url
    assert req_url.endswith("/all")

    # DB confirma persistência via macro_repository (não peek directo)
    recent = mr.get_recent("bis_credit_gap_pt", n=5)
    assert len(recent) == 2
    values = {r["value"] for r in recent}
    assert values == {3.5, 12.8}


def test_fetch_one_html_response_yields_botwall_error():
    """Mocked HTTP devolve HTML → fetch_one devolve error='botwall',
    zero rows upsertadas, indicador não fica em ok."""
    html = "<!DOCTYPE html><html><body>bot-wall</body></html>"
    resp = _FakeResponse(html, content_type="text/html")
    client = _FakeClient(resp)

    async def _drive():
        # Usa outro indicador para não colidir com o test anterior no
        # mesmo temp DB (embora idempotent, keeps assertions clean).
        return await bis_fetcher.fetch_one(client, "bis_credit_gap_es")

    result = asyncio.run(_drive())
    assert result["ok"] is False
    assert result["error"] == "botwall"
    assert result["n_obs"] == 0
    assert result["n_inserted"] == 0
    # Verifica zero persistência
    recent = mr.get_recent("bis_credit_gap_es", n=5)
    assert recent == []


_TESTS = [
    # A. shape / catalog guards
    ("test_narrow_gap_series_key_regex_covers_all_28",
     test_narrow_gap_series_key_regex_covers_all_28),
    ("test_country_codes_are_uppercase_iso2",
     test_country_codes_are_uppercase_iso2),
    # B. period parsing
    ("test_period_to_iso_quarterly_all_four",
     test_period_to_iso_quarterly_all_four),
    ("test_period_to_iso_compact_and_annual_and_invalid",
     test_period_to_iso_compact_and_annual_and_invalid),
    # C. CSV parser
    ("test_missing_markers_all_variants_filtered",
     test_missing_markers_all_variants_filtered),
    ("test_non_numeric_value_dropped_silently",
     test_non_numeric_value_dropped_silently),
    # D. bot-wall
    ("test_html_response_detected_as_botwall_by_content_type",
     test_html_response_detected_as_botwall_by_content_type),
    ("test_html_response_detected_as_botwall_by_leading_bracket",
     test_html_response_detected_as_botwall_by_leading_bracket),
    ("test_valid_csv_is_not_botwall",
     test_valid_csv_is_not_botwall),
    # E. realistic parse
    ("test_valid_csv_parses_to_observations",
     test_valid_csv_parses_to_observations),
    # F. dependency invariants (bidireccional)
    ("test_no_import_of_quant_bis",
     test_no_import_of_quant_bis),
    ("test_macro_fetcher_does_not_import_bis_fetcher",
     test_macro_fetcher_does_not_import_bis_fetcher),
    # G. end-to-end dry runs
    ("test_fetch_one_end_to_end_upserts_to_sqlite",
     test_fetch_one_end_to_end_upserts_to_sqlite),
    ("test_fetch_one_html_response_yields_botwall_error",
     test_fetch_one_html_response_yields_botwall_error),
]


if __name__ == "__main__":
    for name, fn in _TESTS:
        try:
            fn()
            print(f"OK  {name}")
        except AssertionError as exc:
            print(f"FAIL {name}: {exc}")
            sys.exit(1)
    print(f"\nPASS  {len(_TESTS)}/{len(_TESTS)} bis_fetcher tests")

"""Unit tests para personal-agent/regime.py — classificador puro.

Cobertura mínima do B2:
  - compute_regime_snapshot: 4 casos de borda (todos baixos, todos altos,
    mistos, com None em pelo menos um input)
  - ERP: cape=41.66, ten_year=4.48 → erp ≈ -2.08 (tolerância 0.01)

Adicional (baixo custo, alto valor):
  - Sanity de fronteiras [min, max) — VIX 15 → "normal", VIX 25 → "alto".
  - computed_at é ISO 8601 com timezone.

Runnable both ways:
    pytest personal-agent/tests/test_regime.py
    python  personal-agent/tests/test_regime.py

Sem DB, sem secrets, sem HTTP — regime.py é pura.
"""
import os
import sys
from datetime import datetime, timezone

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from regime import (  # noqa: E402
    REGIME_DEF_VERSION,
    REGIME_DEFINITIONS_V1,
    compute_regime_snapshot,
)


def test_all_low_inputs_classify_low_labels():
    """VIX 10, HY 2.5, CAPE 15, 10Y 1.0 →
       baixo / apertado / barato / expandido."""
    snap = compute_regime_snapshot(vix=10.0, hy_oas=2.5, cape=15.0,
                                    ten_year_yield=1.0)
    assert snap["def_version"] == REGIME_DEF_VERSION
    assert snap["regimes"] == {
        "vix": "baixo", "hy_oas": "apertado",
        "cape": "barato", "erp": "expandido",
    }
    expected_erp = 100.0 / 15.0 - 1.0  # 5.6667
    assert abs(snap["derived"]["erp"] - expected_erp) < 1e-3


def test_all_high_inputs_classify_high_labels():
    """VIX 35, HY 8.0, CAPE 45, 10Y 6.0 →
       alto / stress / extremo / comprimido."""
    snap = compute_regime_snapshot(vix=35.0, hy_oas=8.0, cape=45.0,
                                    ten_year_yield=6.0)
    assert snap["regimes"] == {
        "vix": "alto", "hy_oas": "stress",
        "cape": "extremo", "erp": "comprimido",
    }
    # erp = 100/45 - 6 ≈ -3.78 → comprimido (< 1.0)
    assert snap["derived"]["erp"] < 1.0


def test_mixed_middle_inputs_classify_all_normal():
    """VIX 20, HY 4.0, CAPE 25, 10Y 2.0 → todos 'normal'."""
    snap = compute_regime_snapshot(vix=20.0, hy_oas=4.0, cape=25.0,
                                    ten_year_yield=2.0)
    assert snap["regimes"] == {
        "vix": "normal", "hy_oas": "normal",
        "cape": "normal", "erp": "normal",
    }
    # erp = 100/25 - 2 = 2.0 → normal
    assert abs(snap["derived"]["erp"] - 2.0) < 1e-6


def test_partial_none_inputs_produce_partial_snapshot():
    """CAPE=None ⇒ regimes.cape=None E derived.erp=None E regimes.erp=None
       (porque ERP depende de CAPE).
       HY OAS=None ⇒ apenas regimes.hy_oas=None.
       VIX e 10Y presentes → classificam normalmente.
       Snapshot é emitido; nada rebenta."""
    snap = compute_regime_snapshot(vix=16.0, hy_oas=None, cape=None,
                                    ten_year_yield=4.5)
    assert snap["regimes"]["vix"] == "normal"
    assert snap["regimes"]["hy_oas"] is None
    assert snap["regimes"]["cape"] is None
    assert snap["regimes"]["erp"] is None
    assert snap["derived"]["erp"] is None
    assert snap["inputs"] == {"vix": 16.0, "hy_oas": None,
                              "cape": None, "ten_year": 4.5}
    assert snap["def_version"] == REGIME_DEF_VERSION


def test_erp_matches_docstring_example():
    """Exemplo do brief: cape=41.66, ten_year=4.48 → erp ≈ -2.08 (tol 0.01).
       Confirma também a interpretação: cape 'extremo', erp 'comprimido'."""
    snap = compute_regime_snapshot(vix=16.59, hy_oas=2.75, cape=41.66,
                                    ten_year_yield=4.48)
    assert abs(snap["derived"]["erp"] - (-2.08)) < 0.01, snap["derived"]
    assert snap["regimes"]["cape"] == "extremo"
    assert snap["regimes"]["erp"] == "comprimido"


def test_boundary_vix_15_goes_to_normal_not_baixo():
    """Convenção [min, max): VIX=15 cai no bucket [15, 25) = 'normal'."""
    snap = compute_regime_snapshot(vix=15.0, hy_oas=3.5, cape=20.0,
                                    ten_year_yield=4.0)
    assert snap["regimes"]["vix"] == "normal"


def test_boundary_vix_25_goes_to_alto_not_normal():
    """VIX=25 cai no bucket [25, +inf) = 'alto'."""
    snap = compute_regime_snapshot(vix=25.0, hy_oas=3.5, cape=20.0,
                                    ten_year_yield=4.0)
    assert snap["regimes"]["vix"] == "alto"


def test_computed_at_is_iso_utc():
    """Metadata: computed_at deve ser ISO 8601 com timezone UTC."""
    snap = compute_regime_snapshot(vix=15.0, hy_oas=3.5, cape=20.0,
                                    ten_year_yield=4.0)
    parsed = datetime.fromisoformat(snap["computed_at"])
    assert parsed.tzinfo is not None, snap["computed_at"]
    # Compara o offset como número de segundos — dispensa expiring APIs.
    assert parsed.utcoffset() == timezone.utc.utcoffset(parsed)


_TESTS = [
    ("test_all_low_inputs_classify_low_labels",     test_all_low_inputs_classify_low_labels),
    ("test_all_high_inputs_classify_high_labels",   test_all_high_inputs_classify_high_labels),
    ("test_mixed_middle_inputs_classify_all_normal",test_mixed_middle_inputs_classify_all_normal),
    ("test_partial_none_inputs_produce_partial_snapshot",
                                                    test_partial_none_inputs_produce_partial_snapshot),
    ("test_erp_matches_docstring_example",          test_erp_matches_docstring_example),
    ("test_boundary_vix_15_goes_to_normal_not_baixo",
                                                    test_boundary_vix_15_goes_to_normal_not_baixo),
    ("test_boundary_vix_25_goes_to_alto_not_normal",
                                                    test_boundary_vix_25_goes_to_alto_not_normal),
    ("test_computed_at_is_iso_utc",                 test_computed_at_is_iso_utc),
]

if __name__ == "__main__":
    for name, fn in _TESTS:
        try:
            fn()
            print(f"OK  {name}")
        except AssertionError as exc:
            print(f"FAIL {name}: {exc}")
            sys.exit(1)
    print(f"\nPASS  {len(_TESTS)}/{len(_TESTS)} regime.py tests")

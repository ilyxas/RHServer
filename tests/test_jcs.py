from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from hypothesis import given
from hypothesis import strategies as st

from rh_common.jcs import JCSError, canonicalize, canonicalize_text, format_number

VECTORS = json.loads(
    (Path(__file__).parent.parent / "contracts/vectors/jcs.json").read_text(encoding="utf-8")
)["vectors"]
OK = [v for v in VECTORS if not v.get("expect_error")]
BAD = [v for v in VECTORS if v.get("expect_error")]


@pytest.mark.parametrize("v", OK, ids=[v["name"] for v in OK])
def test_vector(v: dict[str, Any]) -> None:
    out = canonicalize_text(v["input"])
    assert out.decode("utf-8") == v["expected"]
    assert out.hex() == v["expected_hex"]


@pytest.mark.parametrize("v", BAD, ids=[v["name"] for v in BAD])
def test_vector_rejected(v: dict[str, Any]) -> None:
    with pytest.raises(JCSError):
        canonicalize_text(v["input"])


@pytest.mark.parametrize("v", OK, ids=[v["name"] for v in OK])
def test_vector_matches_reference_library(v: dict[str, Any]) -> None:
    # Independent implementation (Trail of Bits) on the same parsed value.
    parsed = json.loads(v["input"])
    assert rfc8785.dumps(_ints_as_doubles(parsed)) == v["expected"].encode("utf-8")


def test_protocol_scope_has_no_fractional_numbers() -> None:
    def walk(x: Any) -> None:
        assert not isinstance(x, float), "protocol vectors must not contain doubles"
        if isinstance(x, dict):
            for item in x.values():
                walk(item)
        elif isinstance(x, list):
            for item in x:
                walk(item)

    for v in OK:
        if v["scope"] == "protocol" and v["name"] != "integer-negative-zero":
            walk(json.loads(v["input"]))


def test_rfc8785_appendix_b_numbers_present() -> None:
    names = {v["name"] for v in VECTORS}
    assert sum(n.startswith("rfc8785-number-") for n in names) == 24


finite = st.floats(allow_nan=False, allow_infinity=False)
json_values = st.recursive(
    st.none() | st.booleans() | finite | st.integers(-(2**53), 2**53) | st.text(),
    lambda children: (
        st.lists(children, max_size=5) | st.dictionaries(st.text(max_size=8), children, max_size=5)
    ),
    max_leaves=20,
)


@given(json_values)
def test_matches_reference_library_on_random_values(value: Any) -> None:
    try:
        expected = rfc8785.dumps(_ints_as_doubles(value))
    except Exception:
        with pytest.raises(JCSError):
            canonicalize(value)
        return
    assert canonicalize(value) == expected


@given(finite)
def test_number_round_trips(x: float) -> None:
    assert float(format_number(x)) == x or (x == 0 and math.copysign(1, x) < 0)


def test_non_finite_rejected() -> None:
    for x in (math.nan, math.inf, -math.inf):
        with pytest.raises(JCSError):
            format_number(x)


def _ints_as_doubles(x: Any) -> Any:
    # JCS treats every number as a double; rfc8785 prints Python ints exactly.
    if isinstance(x, bool) or x is None or isinstance(x, str | float):
        return x
    if isinstance(x, int):
        return float(x)
    if isinstance(x, list):
        return [_ints_as_doubles(i) for i in x]
    return {k: _ints_as_doubles(val) for k, val in x.items()}

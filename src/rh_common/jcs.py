"""JSON Canonicalization Scheme (RFC 8785).

The phone signs canonical JSON and the core verifies it, so both sides must
produce byte-identical output. Behaviour is pinned by contracts/vectors/jcs.json.

Numbers follow RFC 8785 §3.2.2.3: every number is an IEEE 754 double printed
with the ECMAScript Number.prototype.toString algorithm.
"""

from __future__ import annotations

import json
import math
from decimal import Decimal
from typing import Any

__all__ = ["JCSError", "canonicalize", "canonicalize_text", "format_number"]


class JCSError(ValueError):
    """Input cannot be canonicalized (NaN, lone surrogate, duplicate key, ...)."""


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def canonicalize(value: Any) -> bytes:
    """Return the canonical UTF-8 bytes of an already parsed JSON value."""
    parts: list[str] = []
    _write(value, parts)
    return "".join(parts).encode("utf-8")


def canonicalize_text(text: str | bytes) -> bytes:
    """Parse JSON text strictly and return its canonical UTF-8 bytes."""
    return canonicalize(_parse(text))


def format_number(x: float) -> str:
    """ECMAScript Number.prototype.toString for a finite double."""
    if not math.isfinite(x):
        raise JCSError(f"number is not finite: {x!r}")
    if x == 0:
        return "0"  # also -0
    sign = "-" if x < 0 else ""
    # repr() gives the shortest round-trip digits, which is what ES uses.
    t = Decimal(repr(abs(x))).normalize().as_tuple()
    digits = "".join(map(str, t.digits))
    assert isinstance(t.exponent, int)
    k = len(digits)
    n = t.exponent + k  # value = 0.digits × 10^n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def _write(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        _write_string(value, out)
    elif isinstance(value, int):
        out.append(format_number(_int_to_double(value)))
    elif isinstance(value, float):
        out.append(format_number(value))
    elif isinstance(value, dict):
        _write_object(value, out)
    elif isinstance(value, list | tuple):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write(item, out)
        out.append("]")
    else:
        raise JCSError(f"unsupported type: {type(value).__name__}")


def _write_object(obj: dict[Any, Any], out: list[str]) -> None:
    for key in obj:
        if not isinstance(key, str):
            raise JCSError(f"object key is not a string: {key!r}")
    # RFC 8785 §3.2.3: sort by UTF-16 code units, not by code points.
    keys = sorted(obj, key=_utf16_key)
    out.append("{")
    for i, key in enumerate(keys):
        if i:
            out.append(",")
        _write_string(key, out)
        out.append(":")
        _write(obj[key], out)
    out.append("}")


def _write_string(s: str, out: list[str]) -> None:
    out.append('"')
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ch < " ":
            out.append(f"\\u{ord(ch):04x}")
        elif "\ud800" <= ch <= "\udfff":
            raise JCSError("string contains a lone surrogate")
        else:
            out.append(ch)
    out.append('"')


def _utf16_key(s: str) -> bytes:
    try:
        return s.encode("utf-16-be")
    except UnicodeEncodeError as e:
        raise JCSError("object key contains a lone surrogate") from e


def _int_to_double(i: int) -> float:
    try:
        return float(i)
    except OverflowError as e:
        raise JCSError(f"integer out of double range: {i}") from e


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise JCSError(f"duplicate object key: {key!r}")
        obj[key] = value
    return obj


def _reject_constant(name: str) -> Any:
    raise JCSError(f"not valid JSON: {name}")


def _parse(text: str | bytes) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_float=float,
            parse_int=int,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as e:
        raise JCSError(f"not valid JSON: {e}") from e

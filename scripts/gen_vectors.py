"""Generate contracts/vectors/*.json.

Run: uv run python scripts/gen_vectors.py
The output is deterministic; tests fail if the committed files differ from it.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import vectors_trust  # noqa: E402
from rh_common.jcs import JCSError, canonicalize_text  # noqa: E402

VECTORS = ROOT / "contracts" / "vectors"

# (name, scope, raw JSON input). scope "protocol" is what signed objects use:
# strings, integers, arrays, nesting. Both sides must pass it.
# scope "full" adds doubles and error cases; only the server must pass it.
JCS_CASES: list[tuple[str, str, str]] = [
    ("empty-object", "protocol", "{}"),
    ("empty-array", "protocol", "[]"),
    ("literals", "protocol", "[null, true, false]"),
    ("whitespace-removed", "protocol", ' { "b" : 1 ,\n\t"a" : [ 1 , 2 ] } '),
    ("key-order-ascii", "protocol", '{"b":2,"a":1,"c":3,"A":0,"_":4,"1":5}'),
    ("key-order-prefix", "protocol", '{"ab":1,"a":2,"abc":3,"":4}'),
    (
        "key-order-utf16-rfc8785",
        "protocol",
        '{"\\u20ac":"Euro Sign","\\r":"Carriage Return",'
        '"\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One",'
        '"\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control",'
        '"\\u00f6":"Latin Small Letter O With Diaeresis"}',
    ),
    ("key-order-emoji-vs-bmp", "protocol", '{"\\uffff":1,"\\ud83d\\ude00":2,"\\ue000":3}'),
    ("nested-objects-sorted", "protocol", '{"z":{"b":1,"a":{"d":2,"c":3}},"y":[{"b":1,"a":2}]}'),
    ("array-order-kept", "protocol", '["b","a",3,1,[2,1]]'),
    (
        "string-escapes",
        "protocol",
        '"quote\\" backslash\\\\ slash\\/ tab\\t nl\\n cr\\r bs\\b ff\\f"',
    ),
    ("string-control-chars", "protocol", '"\\u0000\\u0001\\u001f\\u007f"'),
    ("string-unicode-literal", "protocol", '"\\u00e9 \\u0416 \\u4e2d \\ud83d\\ude00 \\u2028"'),
    ("string-utf8-input", "protocol", '"Привет, мир — €"'),
    (
        "integers",
        "protocol",
        "[0, 1, -1, 60, 120, 1700000000, 9007199254740991, -9007199254740991]",
    ),
    ("integer-negative-zero", "protocol", "-0"),
    (
        "signing-object",
        "protocol",
        '{"v":1,"device":"3f2a9c0d1e4b5a6f7081928374655647","key":"normal",'
        '"nonce":"q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=",'
        '"ts":"2026-10-19T12:00:00Z","exp":"2026-10-19T12:01:00Z","op":"ping",'
        '"body":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}',
    ),
    (
        "approval-like-object",
        "protocol",
        '{"what":"Удаление каталога","command":"rm -rf ~/tmp/build",'
        '"paths":["/Users/owner/tmp/build"],"urls":[],"explain":"чистка \\"кэша\\"",'
        '"n":3}',
    ),
    (
        "rfc8785-example",
        "full",
        '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],'
        '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
        '"literals":[null,true,false]}',
    ),
    ("number-forms", "full", "[1.0, 1e0, 10e-1, 100, 1e2, 1E+2, 0.5, -0.0, 1.5e300]"),
    ("integer-beyond-2^53", "full", "[9007199254740993, 18446744073709551616]"),
]

# RFC 8785 Appendix B: IEEE 754 bit pattern → expected text.
RFC8785_NUMBERS: list[tuple[str, str]] = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]

# Inputs that must be rejected (scope "full").
JCS_ERRORS: list[tuple[str, str]] = [
    ("duplicate-key", '{"a":1,"a":2}'),
    ("lone-surrogate-value", '"\\ud800"'),
    ("lone-surrogate-key", '{"\\udc00":1}'),
    ("nan", "NaN"),
    ("infinity-overflow", "1e400"),
    ("not-json", "{a:1}"),
]


def _ieee(hex_bits: str) -> str:
    value = struct.unpack(">d", bytes.fromhex(hex_bits))[0]
    return repr(value)


def jcs_vectors() -> dict[str, Any]:
    vectors: list[dict[str, Any]] = []
    for name, scope, raw in JCS_CASES:
        vectors.append(_ok(name, scope, raw))
    for bits, expected in RFC8785_NUMBERS:
        v = _ok(f"rfc8785-number-{bits}", "full", _ieee(bits))
        if v["expected"] != expected:
            raise SystemExit(f"{bits}: got {v['expected']}, RFC says {expected}")
        vectors.append(v)
    for name, raw in JCS_ERRORS:
        try:
            canonicalize_text(raw)
        except JCSError:
            vectors.append({"name": name, "scope": "full", "input": raw, "expect_error": True})
        else:
            raise SystemExit(f"{name}: expected an error")
    return {
        "description": (
            "RFC 8785 canonical JSON. input is raw JSON text; expected is the canonical "
            "text, expected_hex its UTF-8 bytes. Vectors with expect_error=true must be rejected. "
            "scope=protocol is required on both sides; scope=full on the server."
        ),
        "version": 1,
        "vectors": vectors,
    }


def _ok(name: str, scope: str, raw: str) -> dict[str, Any]:
    out = canonicalize_text(raw)
    return {
        "name": name,
        "scope": scope,
        "input": raw,
        "expected": out.decode("utf-8"),
        "expected_hex": out.hex(),
        "expected_sha256": hashlib.sha256(out).hexdigest(),
    }


def render(doc: dict[str, Any]) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


GENERATED = {"jcs.json": jcs_vectors, **vectors_trust.GENERATED}


def main() -> int:
    VECTORS.mkdir(parents=True, exist_ok=True)
    for filename, build in GENERATED.items():
        (VECTORS / filename).write_text(render(build()), encoding="utf-8")
        print(f"wrote contracts/vectors/{filename}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

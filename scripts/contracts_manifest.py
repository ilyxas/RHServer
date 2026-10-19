"""Write or check contracts/MANIFEST.sha256.

Format is the one `sha256sum` prints: "<hex>  <path relative to contracts/>",
sorted by path, the manifest itself excluded. The root hash that RHClient keeps
in contracts/UPSTREAM is the sha256 of the manifest file's bytes.

  uv run python scripts/contracts_manifest.py          # rewrite the manifest
  uv run python scripts/contracts_manifest.py --check  # exit 1 if it is stale
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

CONTRACTS = Path(__file__).resolve().parent.parent / "contracts"
MANIFEST = "MANIFEST.sha256"
IGNORED = {MANIFEST, ".DS_Store"}


def build(root: Path = CONTRACTS) -> str:
    lines = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name not in IGNORED):
        rel = path.relative_to(root).as_posix()
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {rel}\n")
    return "".join(sorted(lines, key=lambda line: line.split("  ", 1)[1]))


def root_hash(manifest_text: str) -> str:
    return hashlib.sha256(manifest_text.encode("utf-8")).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    expected = build()
    target = CONTRACTS / MANIFEST
    if args.check:
        current = target.read_text(encoding="utf-8") if target.exists() else ""
        if current != expected:
            print("contracts/MANIFEST.sha256 is stale: run scripts/contracts_manifest.py")
            return 1
        print(f"ok, root hash {root_hash(current)}")
        return 0
    target.write_text(expected, encoding="utf-8")
    print(f"wrote contracts/{MANIFEST}, root hash {root_hash(expected)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

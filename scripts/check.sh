#!/usr/bin/env bash
# Everything a PR must pass. Run on the cloud container and on Илья's Mac;
# the Mac output goes into the PR description.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== $(uname -sm), $(uv run python --version)"
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run python scripts/contracts_manifest.py --check
uv run pytest "$@"

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import yaml
from openapi_spec_validator import validate

ROOT = Path(__file__).parent.parent


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_openapi_is_valid() -> None:
    validate(yaml.safe_load((ROOT / "contracts/api/openapi.yaml").read_text(encoding="utf-8")))


def test_every_operation_has_op_and_key_level() -> None:
    doc = yaml.safe_load((ROOT / "contracts/api/openapi.yaml").read_text(encoding="utf-8"))
    for path, item in doc["paths"].items():
        for method, op in item.items():
            if method in {"get", "post", "put", "delete", "patch"}:
                assert op.get("x-rh-op"), f"{method} {path}: missing x-rh-op"
                assert op.get("x-rh-key") in {"normal", "critical", "none"}, f"{method} {path}"


def test_vectors_match_generator() -> None:
    gen = _load("gen_vectors")
    for filename, build in gen.GENERATED.items():
        committed = (ROOT / "contracts/vectors" / filename).read_text(encoding="utf-8")
        assert committed == gen.render(build()), f"{filename} is stale: run gen_vectors.py"


def test_manifest_is_current() -> None:
    manifest = _load("contracts_manifest")
    committed = (ROOT / "contracts/MANIFEST.sha256").read_text(encoding="utf-8")
    assert committed == manifest.build(), "MANIFEST.sha256 is stale: run contracts_manifest.py"


def test_manifest_format() -> None:
    lines = (ROOT / "contracts/MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
    paths = [line.split("  ", 1)[1] for line in lines]
    assert paths == sorted(paths)
    assert "MANIFEST.sha256" not in paths
    for line in lines:
        digest, _ = line.split("  ", 1)
        assert len(digest) == 64 and int(digest, 16) >= 0


def test_vector_files_are_valid_json() -> None:
    for path in (ROOT / "contracts/vectors").glob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))

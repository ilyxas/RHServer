from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).parent.parent
OPENAPI_URI = "urn:rh:openapi"


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
                assert op.get("x-rh-key") in {"normal", "critical", "none", "normal+critical"}, (
                    f"{method} {path}"
                )


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


def _openapi() -> dict[str, object]:
    doc: dict[str, object] = yaml.safe_load(
        (ROOT / "contracts/api/openapi.yaml").read_text(encoding="utf-8")
    )
    return doc


def openapi_validator(pointer: str) -> Draft202012Validator:
    """A validator for the schema at a JSON pointer inside openapi.yaml, refs resolved."""
    resource = Resource.from_contents(_openapi(), default_specification=DRAFT202012)
    registry: Registry[object] = Registry().with_resource(OPENAPI_URI, resource)
    return Draft202012Validator({"$ref": f"{OPENAPI_URI}#{pointer}"}, registry=registry)


def _examples() -> list[tuple[str, str, object]]:
    doc = _openapi()
    found = []
    paths = doc["paths"]
    assert isinstance(paths, dict)
    for path, item in paths.items():
        esc = path.replace("~", "~0").replace("/", "~1")
        for method, op in item.items():
            bodies = [("requestBody", op.get("requestBody"))]
            bodies += [(f"responses/{code}", r) for code, r in op.get("responses", {}).items()]
            for where, body in bodies:
                for media, content in (body or {}).get("content", {}).items():
                    if "example" in content:
                        mime = media.replace("/", "~1")
                        pointer = f"/paths/{esc}/{method}/{where}/content/{mime}"
                        found.append((f"{method} {path} {where}", pointer, content["example"]))
    return found


@pytest.mark.parametrize(("name", "pointer", "example"), _examples(), ids=lambda v: str(v)[:40])
def test_openapi_examples_match_schemas(name: str, pointer: str, example: object) -> None:
    errors = list(openapi_validator(pointer + "/schema").iter_errors(example))
    assert not errors, f"{name}: {errors[0].message}"


def test_stage2_examples_exist() -> None:
    names = {name for name, _, _ in _examples()}
    for op in ("post /v1/data", "post /v1/log", "get /v1/quick"):
        assert any(n.startswith(op) and "responses/200" in n for n in names), op


def test_data_value_shapes() -> None:
    check = openapi_validator("/components/schemas/DataResult")
    at = "2026-10-19T12:00:00Z"
    good = [
        {"status": "active", "type": "number", "value": 1.5, "unit": "%", "at": at},
        {"status": "active", "type": "status", "value": {"state": "off"}, "at": at},
        {"status": "active", "type": "rows", "value": [{"id": "a", "title": "A"}], "at": at},
        {
            "status": "active",
            "type": "rows",
            "value": [{"id": "a", "title": "A", "at": at}],
            "at": at,
        },
        {"status": "active", "type": "bool", "value": True, "at": at},
        {"status": "pending"},
        {"status": "error", "message": "provider failed"},
    ]
    bad = [
        {"status": "active", "type": "number", "value": "1", "at": at},
        {"status": "active", "type": "text", "value": "x", "unit": "%", "at": at},
        {"status": "active", "type": "status", "value": {"state": "maybe"}, "at": at},
        {"status": "active", "type": "rows", "value": [{"id": "a"}], "at": at},
        {
            "status": "active",
            "type": "rows",
            "value": [{"id": "a", "title": "A", "at": "now"}],
            "at": at,
        },
        {"status": "pending", "value": 1},
        {"status": "error"},
    ]
    for value in good:
        assert check.is_valid(value), value
    for value in bad:
        assert not check.is_valid(value), value

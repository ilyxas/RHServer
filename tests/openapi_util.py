"""Validate JSON against schemas inside contracts/api/openapi.yaml (refs resolved)."""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).parent.parent
OPENAPI_URI = "urn:rh:openapi"


@cache
def _openapi() -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load(
        (ROOT / "contracts/api/openapi.yaml").read_text(encoding="utf-8")
    )
    return doc


def openapi_validator(pointer: str) -> Draft202012Validator:
    """A validator for the schema at a JSON pointer inside openapi.yaml."""
    resource = Resource.from_contents(_openapi(), default_specification=DRAFT202012)
    registry: Registry[Any] = Registry().with_resource(OPENAPI_URI, resource)
    return Draft202012Validator({"$ref": f"{OPENAPI_URI}#{pointer}"}, registry=registry)


def check_response(path: str, method: str, status: int, body: Any) -> None:
    """Assert `body` fits the documented response of an operation."""
    op = _openapi()["paths"][path][method]
    response = op["responses"][str(status)]
    if "$ref" in response:
        pointer = response["$ref"].removeprefix("#") + "/content/application~1json/schema"
    else:
        esc = path.replace("~", "~0").replace("/", "~1")
        pointer = f"/paths/{esc}/{method}/responses/{status}/content/application~1json/schema"
    errors = list(openapi_validator(pointer).iter_errors(body))
    assert not errors, f"{method} {path} {status}: {errors[0].message} in {body}"

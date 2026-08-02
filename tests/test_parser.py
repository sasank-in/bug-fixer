import json

import pytest

from autoqa.spec.parser import OpenAPISpec, SpecError

MINIMAL = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "paths": {
        "/items/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "schema": {"type": "integer"}}
            ],
            "get": {
                "operationId": "getItem",
                "parameters": [
                    {"name": "verbose", "in": "query", "schema": {"type": "boolean"}}
                ],
                "responses": {"200": {"description": "ok"}},
            },
            "post": {
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Item"}
                        }
                    },
                },
                "responses": {"201": {"description": "created"}},
            },
        }
    },
    "components": {
        "schemas": {
            "Item": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"},
                    "child": {"$ref": "#/components/schemas/Item"},
                },
            }
        }
    },
}


def test_rejects_non_v3():
    with pytest.raises(SpecError):
        OpenAPISpec({"swagger": "2.0", "paths": {}})


def test_extracts_operations():
    spec = OpenAPISpec(MINIMAL)
    ops = spec.operations()
    assert {op.key for op in ops} == {"GET /items/{id}", "POST /items/{id}"}


def test_path_params_are_always_required():
    spec = OpenAPISpec(MINIMAL)
    get = next(o for o in spec.operations() if o.method == "GET")
    id_param = next(p for p in get.parameters if p.name == "id")
    # The spec omits `required`, but OpenAPI mandates it for path params.
    assert id_param.required is True


def test_path_level_params_merge_into_operations():
    spec = OpenAPISpec(MINIMAL)
    get = next(o for o in spec.operations() if o.method == "GET")
    assert {p.name for p in get.parameters} == {"id", "verbose"}


def test_resolves_refs_in_request_body():
    spec = OpenAPISpec(MINIMAL)
    post = next(o for o in spec.operations() if o.method == "POST")
    assert post.body_required is True
    assert post.body_schema["properties"]["name"] == {"type": "string"}


def test_recursive_ref_terminates():
    # `Item.child` points back at Item; resolution must not recurse forever.
    spec = OpenAPISpec(MINIMAL)
    post = next(o for o in spec.operations() if o.method == "POST")
    assert post.body_schema["properties"]["child"] == {}


def test_loads_yaml_file(tmp_path):
    import yaml

    path = tmp_path / "spec.yaml"
    path.write_text(yaml.safe_dump(MINIMAL), encoding="utf-8")
    assert len(OpenAPISpec.from_file(path).operations()) == 2


def test_loads_json_file(tmp_path):
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(MINIMAL), encoding="utf-8")
    assert len(OpenAPISpec.from_file(path).operations()) == 2

"""Parse an OpenAPI 3.x document into a flat list of fuzzable operations."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

ParamLocation = Literal["path", "query", "header", "cookie"]

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")


@dataclass(frozen=True)
class Parameter:
    name: str
    location: ParamLocation
    required: bool
    schema: dict[str, Any]


@dataclass(frozen=True)
class Operation:
    """One fuzzable (method, path) pair with its resolved parameter schemas."""

    operation_id: str
    method: str
    path: str
    parameters: tuple[Parameter, ...] = ()
    body_schema: dict[str, Any] | None = None
    body_required: bool = False
    security: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"


class SpecError(ValueError):
    """Raised when a document is not usable as an OpenAPI 3 spec."""


class OpenAPISpec:
    """A loaded OpenAPI document with $ref resolution and operation extraction."""

    def __init__(self, document: dict[str, Any]) -> None:
        if not isinstance(document, dict):
            raise SpecError("spec root must be a mapping")
        version = str(document.get("openapi", ""))
        if not version.startswith("3."):
            raise SpecError(
                f"unsupported spec version {version!r}; only OpenAPI 3.x is supported"
            )
        self.document = document
        self._ref_cache: dict[str, Any] = {}

    @classmethod
    def from_file(cls, path: str | Path) -> OpenAPISpec:
        p = Path(path)
        raw = p.read_text(encoding="utf-8")
        if p.suffix.lower() in {".yaml", ".yml"}:
            document = yaml.safe_load(raw)
        else:
            try:
                document = json.loads(raw)
            except json.JSONDecodeError:
                # Some specs are served as .txt/no-extension but are really YAML.
                document = yaml.safe_load(raw)
        return cls(document)

    # -- $ref resolution ---------------------------------------------------

    def resolve(self, node: Any, _seen: frozenset[str] = frozenset()) -> Any:
        """Recursively inline local $refs. Remote refs are left untouched.

        Cycles are broken by returning an empty schema, which the generator
        treats as "anything goes" rather than recursing forever.
        """
        if isinstance(node, list):
            return [self.resolve(item, _seen) for item in node]
        if not isinstance(node, dict):
            return node

        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/"):
            if ref in _seen:
                return {}
            target = self._lookup_pointer(ref)
            resolved = self.resolve(target, _seen | {ref})
            # Sibling keys alongside $ref override the target (OpenAPI 3.1).
            siblings = {k: v for k, v in node.items() if k != "$ref"}
            if siblings:
                merged = dict(resolved) if isinstance(resolved, dict) else {}
                merged.update(self.resolve(siblings, _seen))
                return merged
            return resolved

        return {k: self.resolve(v, _seen) for k, v in node.items()}

    def _lookup_pointer(self, ref: str) -> Any:
        if ref in self._ref_cache:
            return self._ref_cache[ref]
        node: Any = self.document
        for token in ref.removeprefix("#/").split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            if isinstance(node, list):
                node = node[int(token)]
            elif isinstance(node, dict) and token in node:
                node = node[token]
            else:
                raise SpecError(f"cannot resolve $ref {ref!r}")
        self._ref_cache[ref] = node
        return node

    # -- operation extraction ---------------------------------------------

    @property
    def base_paths(self) -> list[str]:
        servers = self.document.get("servers") or []
        return [s.get("url", "") for s in servers if isinstance(s, dict)]

    def operations(self) -> list[Operation]:
        return list(self._iter_operations())

    def _iter_operations(self) -> Iterator[Operation]:
        paths = self.document.get("paths") or {}
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            path_item = self.resolve(path_item)
            shared = self._parameters(path_item.get("parameters"))
            for method in HTTP_METHODS:
                op = path_item.get(method)
                if not isinstance(op, dict):
                    continue
                params = shared + self._parameters(op.get("parameters"))
                # Later definitions win on (name, location) collisions.
                deduped: dict[tuple[str, str], Parameter] = {}
                for prm in params:
                    deduped[(prm.name, prm.location)] = prm

                body_schema, body_required = self._request_body(op.get("requestBody"))
                security = tuple(
                    name
                    for entry in (op.get("security") or self.document.get("security") or [])
                    if isinstance(entry, dict)
                    for name in entry
                )
                yield Operation(
                    operation_id=op.get("operationId") or f"{method}_{path}",
                    method=method.upper(),
                    path=path,
                    parameters=tuple(deduped.values()),
                    body_schema=body_schema,
                    body_required=body_required,
                    security=security,
                )

    def _parameters(self, raw: Any) -> list[Parameter]:
        if not isinstance(raw, list):
            return []
        out: list[Parameter] = []
        for item in raw:
            item = self.resolve(item)
            if not isinstance(item, dict) or "name" not in item:
                continue
            location = item.get("in", "query")
            if location not in ("path", "query", "header", "cookie"):
                continue
            out.append(
                Parameter(
                    name=item["name"],
                    location=location,
                    # Path params are always required per the OpenAPI spec.
                    required=bool(item.get("required")) or location == "path",
                    schema=item.get("schema") or {},
                )
            )
        return out

    def _request_body(self, raw: Any) -> tuple[dict[str, Any] | None, bool]:
        if not isinstance(raw, dict):
            return None, False
        raw = self.resolve(raw)
        content = raw.get("content") or {}
        for media_type in ("application/json", "text/json", "*/*"):
            if media_type in content:
                schema = content[media_type].get("schema")
                return (schema if isinstance(schema, dict) else {}), bool(raw.get("required"))
        # Fall back to the first declared media type with a schema.
        for payload in content.values():
            if isinstance(payload, dict) and isinstance(payload.get("schema"), dict):
                return payload["schema"], bool(raw.get("required"))
        return None, bool(raw.get("required"))

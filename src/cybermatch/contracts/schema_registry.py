"""Machine-readable schema registry for repository and external assets."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Mapping

from jsonschema import Draft202012Validator


class AssetSchemaError(ValueError):
    """Raised when a registered CyberMatch asset violates its JSON Schema."""


@dataclass(frozen=True)
class AssetSchemaRegistration:
    name: str
    schema_file: str
    glob: str


@dataclass(frozen=True)
class AssetValidationSummary:
    schema_version: str
    counts: Mapping[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


class SchemaRegistry:
    def __init__(self) -> None:
        schema_root = files("src.cybermatch.schemas")
        registry = json.loads(schema_root.joinpath("registry.json").read_text(encoding="utf-8"))
        if registry.get("schema_version") != "1.0":
            raise AssetSchemaError("unsupported schema registry version")
        self.schema_version = registry["schema_version"]
        self._schema_root = schema_root
        self._registrations = tuple(
            AssetSchemaRegistration(
                name=item["name"],
                schema_file=item["schema"],
                glob=item["glob"],
            )
            for item in registry["assets"]
        )
        names = [item.name for item in self._registrations]
        if len(names) != len(set(names)):
            raise AssetSchemaError("schema registry names must be unique")

    @property
    def registrations(self) -> tuple[AssetSchemaRegistration, ...]:
        return self._registrations

    def schema(self, name: str) -> dict[str, object]:
        registration = next((item for item in self._registrations if item.name == name), None)
        if registration is None:
            raise AssetSchemaError(f"unknown schema: {name}")
        payload = json.loads(
            self._schema_root.joinpath(registration.schema_file).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(payload)
        return payload

    def validate(self, name: str, payload: object, *, source: str = "<memory>") -> None:
        validator = Draft202012Validator(self.schema(name))
        errors = sorted(validator.iter_errors(payload), key=lambda item: tuple(str(part) for part in item.path))
        if errors:
            first = errors[0]
            location = ".".join(str(part) for part in first.absolute_path) or "<root>"
            raise AssetSchemaError(f"{source}: {location}: {first.message}")

    def validate_repository(self, repository_root: Path) -> AssetValidationSummary:
        root = repository_root.resolve()
        counts: dict[str, int] = {}
        for registration in self._registrations:
            paths = sorted(root.glob(registration.glob))
            if not paths:
                raise AssetSchemaError(
                    f"registry pattern {registration.glob!r} for {registration.name!r} matched no files"
                )
            for path in paths:
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    raise AssetSchemaError(f"{path}: invalid JSON: {exc}") from exc
                self.validate(registration.name, payload, source=path.relative_to(root).as_posix())
            counts[registration.name] = len(paths)
        return AssetValidationSummary(
            schema_version=self.schema_version,
            counts=dict(sorted(counts.items())),
        )


__all__ = [
    "AssetSchemaError",
    "AssetSchemaRegistration",
    "AssetValidationSummary",
    "SchemaRegistry",
]

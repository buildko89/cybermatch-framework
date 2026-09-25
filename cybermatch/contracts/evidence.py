"""Versioned, deterministic contracts for CyberMatch evaluation evidence."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Mapping, Sequence, TypeAlias

from .canonical import canonical_sha256


RUN_CONTRACT_VERSION = "1.0"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MetricScalar: TypeAlias = str | int | float | bool | None


class ContractValidationError(ValueError):
    """Raised when evaluation evidence violates the stable public contract."""


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractValidationError(f"{name} must be a non-empty string")
    return value


def _sha256(value: object, name: str) -> str:
    digest = _text(value, name).lower()
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise ContractValidationError(f"{name} must be a lowercase SHA-256 digest")
    return digest


def _relative_path(value: object) -> str:
    path = PurePosixPath(_text(value, "path").replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or str(path) in {"", "."}:
        raise ContractValidationError("path must be a normalized relative path")
    return str(path)


def _immutable_hashes(values: Mapping[str, str]) -> Mapping[str, str]:
    normalized: dict[str, str] = {}
    for key, value in values.items():
        normalized[_text(key, "input_hashes key")] = _sha256(value, f"input_hashes[{key!r}]")
    return MappingProxyType(dict(sorted(normalized.items())))


@dataclass(frozen=True)
class RunManifest:
    run_id: str
    runner: str
    scenario_id: str
    seed: int
    framework_version: str
    code_revision: str
    dependency_lock_sha256: str
    input_hashes: Mapping[str, str]
    created_at: str
    schema_version: str = RUN_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RUN_CONTRACT_VERSION:
            raise ContractValidationError(f"schema_version must be {RUN_CONTRACT_VERSION!r}")
        for name in ("run_id", "runner", "scenario_id", "framework_version", "code_revision", "created_at"):
            _text(getattr(self, name), name)
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ContractValidationError("seed must be an integer")
        object.__setattr__(
            self,
            "dependency_lock_sha256",
            _sha256(self.dependency_lock_sha256, "dependency_lock_sha256"),
        )
        if not isinstance(self.input_hashes, Mapping) or not self.input_hashes:
            raise ContractValidationError("input_hashes must be a non-empty mapping")
        object.__setattr__(self, "input_hashes", _immutable_hashes(self.input_hashes))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "runner": self.runner,
            "scenario_id": self.scenario_id,
            "seed": self.seed,
            "framework_version": self.framework_version,
            "code_revision": self.code_revision,
            "dependency_lock_sha256": self.dependency_lock_sha256,
            "input_hashes": dict(self.input_hashes),
            "created_at": self.created_at,
        }

    @property
    def manifest_hash(self) -> str:
        return canonical_sha256(self.to_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "RunManifest":
        expected = {
            "schema_version", "run_id", "runner", "scenario_id", "seed",
            "framework_version", "code_revision", "dependency_lock_sha256",
            "input_hashes", "created_at",
        }
        unknown = set(payload) - expected
        missing = expected - set(payload)
        if unknown or missing:
            raise ContractValidationError(
                f"RunManifest fields mismatch; missing={sorted(missing)}, unknown={sorted(unknown)}"
            )
        hashes = payload["input_hashes"]
        if not isinstance(hashes, Mapping):
            raise ContractValidationError("input_hashes must be a mapping")
        return cls(
            schema_version=payload["schema_version"],
            run_id=payload["run_id"],
            runner=payload["runner"],
            scenario_id=payload["scenario_id"],
            seed=payload["seed"],
            framework_version=payload["framework_version"],
            code_revision=payload["code_revision"],
            dependency_lock_sha256=payload["dependency_lock_sha256"],
            input_hashes=hashes,
            created_at=payload["created_at"],
        )


@dataclass(frozen=True)
class MetricSet:
    values: Mapping[str, MetricScalar]
    schema_version: str = RUN_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RUN_CONTRACT_VERSION:
            raise ContractValidationError(f"schema_version must be {RUN_CONTRACT_VERSION!r}")
        if not isinstance(self.values, Mapping):
            raise ContractValidationError("values must be a mapping")
        normalized: dict[str, MetricScalar] = {}
        for key, value in self.values.items():
            name = _text(key, "metric name")
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise ContractValidationError(f"metric {name!r} must be a JSON scalar")
            if isinstance(value, float) and not math.isfinite(value):
                raise ContractValidationError(f"metric {name!r} must be finite")
            normalized[name] = value
        object.__setattr__(self, "values", MappingProxyType(dict(sorted(normalized.items()))))

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": self.schema_version, "values": dict(self.values)}

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "MetricSet":
        if set(payload) != {"schema_version", "values"} or not isinstance(payload["values"], Mapping):
            raise ContractValidationError("MetricSet requires only schema_version and values")
        return cls(values=payload["values"], schema_version=payload["schema_version"])


@dataclass(frozen=True)
class EvidenceArtifact:
    path: str
    sha256: str
    size_bytes: int
    role: str
    media_type: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _relative_path(self.path))
        object.__setattr__(self, "sha256", _sha256(self.sha256, "sha256"))
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int) or self.size_bytes < 0:
            raise ContractValidationError("size_bytes must be a non-negative integer")
        _text(self.role, "role")
        _text(self.media_type, "media_type")

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "role": self.role,
            "media_type": self.media_type,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "EvidenceArtifact":
        if set(payload) != {"path", "sha256", "size_bytes", "role", "media_type"}:
            raise ContractValidationError("EvidenceArtifact fields mismatch")
        return cls(**payload)


@dataclass(frozen=True)
class EvaluationRun:
    manifest: RunManifest
    metrics: MetricSet
    artifacts: tuple[EvidenceArtifact, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, RunManifest) or not isinstance(self.metrics, MetricSet):
            raise ContractValidationError("manifest and metrics must use typed contracts")
        artifacts = tuple(self.artifacts)
        if any(not isinstance(item, EvidenceArtifact) for item in artifacts):
            raise ContractValidationError("artifacts must contain EvidenceArtifact values")
        paths = [item.path for item in artifacts]
        if len(paths) != len(set(paths)):
            raise ContractValidationError("artifact paths must be unique")
        object.__setattr__(self, "artifacts", tuple(sorted(artifacts, key=lambda item: item.path)))

    def to_dict(self) -> dict[str, object]:
        return {
            "manifest": self.manifest.to_dict(),
            "metrics": self.metrics.to_dict(),
            "artifacts": [item.to_dict() for item in self.artifacts],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "EvaluationRun":
        if set(payload) != {"manifest", "metrics", "artifacts"}:
            raise ContractValidationError("EvaluationRun fields mismatch")
        manifest = payload["manifest"]
        metrics = payload["metrics"]
        artifacts = payload["artifacts"]
        if not isinstance(manifest, Mapping) or not isinstance(metrics, Mapping):
            raise ContractValidationError("manifest and metrics must be mappings")
        if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes)):
            raise ContractValidationError("artifacts must be a sequence")
        return cls(
            manifest=RunManifest.from_dict(manifest),
            metrics=MetricSet.from_dict(metrics),
            artifacts=tuple(
                EvidenceArtifact.from_dict(item)
                if isinstance(item, Mapping)
                else (_ for _ in ()).throw(ContractValidationError("artifact must be a mapping"))
                for item in artifacts
            ),
        )


@dataclass(frozen=True)
class EvidenceBundle:
    run: EvaluationRun
    bundle_hash: str | None = None
    schema_version: str = RUN_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RUN_CONTRACT_VERSION:
            raise ContractValidationError(f"schema_version must be {RUN_CONTRACT_VERSION!r}")
        if not isinstance(self.run, EvaluationRun):
            raise ContractValidationError("run must be an EvaluationRun")
        calculated = canonical_sha256(self._body())
        if self.bundle_hash is not None and _sha256(self.bundle_hash, "bundle_hash") != calculated:
            raise ContractValidationError("bundle_hash verification failed")
        object.__setattr__(self, "bundle_hash", calculated)

    def _body(self) -> dict[str, object]:
        return {"schema_version": self.schema_version, "run": self.run.to_dict()}

    def to_dict(self) -> dict[str, object]:
        return {**self._body(), "bundle_hash": self.bundle_hash}

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "EvidenceBundle":
        if set(payload) != {"schema_version", "run", "bundle_hash"}:
            raise ContractValidationError("EvidenceBundle fields mismatch")
        run = payload["run"]
        if not isinstance(run, Mapping):
            raise ContractValidationError("run must be a mapping")
        return cls(
            schema_version=payload["schema_version"],
            run=EvaluationRun.from_dict(run),
            bundle_hash=payload["bundle_hash"],
        )


__all__ = [
    "ContractValidationError",
    "EvaluationRun",
    "EvidenceArtifact",
    "EvidenceBundle",
    "MetricScalar",
    "MetricSet",
    "RUN_CONTRACT_VERSION",
    "RunManifest",
]

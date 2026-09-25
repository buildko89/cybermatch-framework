"""Optional, reproducible anomaly-model plugins for HuntEvent telemetry."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from importlib import metadata
from types import MappingProxyType
from typing import Mapping, Protocol, runtime_checkable

import numpy as np

from .models import (
    Finding,
    GroundTruthLabel,
    HuntEvent,
    SCHEMA_VERSION,
    canonical_json,
    stable_identifier,
)


MODEL_PLUGIN_VERSION = "1.0"
MODEL_KINDS = frozenset({"kmeans_distance", "isolation_forest"})
MODEL_MANIFEST_RELATIVE_PATH = "models/model_manifest.json"


class ThreatHuntingModelError(ValueError):
    """Raised for unavailable, invalid, or unfitted model plugins."""


def _finite_float(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ThreatHuntingModelError(f"{name} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise ThreatHuntingModelError(f"{name} must be a finite number")
    return result


def _freeze_json_mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ThreatHuntingModelError(f"{name} must be a JSON object")
    try:
        normalized = __import__("json").loads(canonical_json(dict(value)))
    except (TypeError, ValueError) as exc:
        raise ThreatHuntingModelError(f"{name} must contain finite JSON values") from exc
    return MappingProxyType(normalized)


@dataclass(frozen=True)
class ModelPluginManifest:
    """Complete provenance needed to reproduce an optional model detector."""

    plugin_id: str
    model_kind: str
    training_data_ids: tuple[str, ...]
    feature_schema: tuple[str, ...]
    feature_schema_hash: str
    preprocessing: Mapping[str, object]
    model_class: str
    model_version: str
    model_hash: str
    random_seed: int
    threshold: float
    calibration: Mapping[str, object]
    schema_version: str = SCHEMA_VERSION
    plugin_version: str = MODEL_PLUGIN_VERSION

    def __post_init__(self) -> None:
        for name in (
            "plugin_id",
            "feature_schema_hash",
            "model_class",
            "model_version",
            "model_hash",
            "schema_version",
            "plugin_version",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ThreatHuntingModelError(f"{name} must be a non-empty string")
        if self.model_kind not in MODEL_KINDS:
            raise ThreatHuntingModelError("model_kind must be a registered optional model")
        training_ids = tuple(self.training_data_ids)
        features = tuple(self.feature_schema)
        if not training_ids or any(not isinstance(item, str) or not item.strip() for item in training_ids):
            raise ThreatHuntingModelError("training_data_ids must contain non-empty strings")
        if len(set(training_ids)) != len(training_ids):
            raise ThreatHuntingModelError("training_data_ids must not contain duplicates")
        if not features or any(not isinstance(item, str) or not item.strip() for item in features):
            raise ThreatHuntingModelError("feature_schema must contain non-empty strings")
        if len(set(features)) != len(features):
            raise ThreatHuntingModelError("feature_schema must not contain duplicates")
        if isinstance(self.random_seed, bool) or not isinstance(self.random_seed, int) or self.random_seed < 0:
            raise ThreatHuntingModelError("random_seed must be a non-negative integer")
        threshold = _finite_float(self.threshold, "threshold")
        object.__setattr__(self, "training_data_ids", training_ids)
        object.__setattr__(self, "feature_schema", features)
        object.__setattr__(self, "threshold", threshold)
        object.__setattr__(self, "preprocessing", _freeze_json_mapping(self.preprocessing, "preprocessing"))
        object.__setattr__(self, "calibration", _freeze_json_mapping(self.calibration, "calibration"))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "plugin_version": self.plugin_version,
            "plugin_id": self.plugin_id,
            "model_kind": self.model_kind,
            "training_data_ids": list(self.training_data_ids),
            "feature_schema": list(self.feature_schema),
            "feature_schema_hash": self.feature_schema_hash,
            "preprocessing": dict(self.preprocessing),
            "model_class": self.model_class,
            "model_version": self.model_version,
            "model_hash": self.model_hash,
            "random_seed": self.random_seed,
            "threshold": self.threshold,
            "calibration": dict(self.calibration),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ModelPluginManifest":
        if not isinstance(payload, Mapping):
            raise ThreatHuntingModelError("model manifest must be an object")
        data = dict(payload)
        data["training_data_ids"] = tuple(data.get("training_data_ids", ()))
        data["feature_schema"] = tuple(data.get("feature_schema", ()))
        try:
            return cls(**data)
        except TypeError as exc:
            raise ThreatHuntingModelError(f"invalid model manifest fields: {exc}") from exc


@dataclass(frozen=True)
class ModelDetectionResult:
    manifest: ModelPluginManifest
    findings: tuple[Finding, ...]
    event_scores: Mapping[str, float]

    def __post_init__(self) -> None:
        if any(not isinstance(item, Finding) for item in self.findings):
            raise ThreatHuntingModelError("findings must contain Finding values")
        scores = {key: _finite_float(value, f"event_scores.{key}") for key, value in self.event_scores.items()}
        object.__setattr__(self, "event_scores", MappingProxyType(scores))


@runtime_checkable
class ThreatHuntingModelPlugin(Protocol):
    def fit(
        self,
        events: tuple[HuntEvent, ...],
        *,
        training_data_ids: tuple[str, ...],
    ) -> ModelPluginManifest: ...

    def detect(self, events: tuple[HuntEvent, ...]) -> ModelDetectionResult: ...


def _feature_value(event: HuntEvent, feature: str) -> float:
    if feature.startswith("attributes."):
        value = event.attributes.get(feature.split(".", 1)[1])
    elif feature in {"step", "source_node", "target_node"}:
        value = getattr(event, feature)
    else:
        raise ThreatHuntingModelError(f"unsupported numeric feature: {feature}")
    if value is None:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ThreatHuntingModelError(f"feature {feature} must contain numeric values")
    result = float(value)
    if not math.isfinite(result):
        raise ThreatHuntingModelError(f"feature {feature} must contain finite values")
    return result


def _matrix(events: tuple[HuntEvent, ...], features: tuple[str, ...]) -> np.ndarray:
    if not events:
        raise ThreatHuntingModelError("model input must contain events")
    if any(not isinstance(event, HuntEvent) for event in events):
        raise ThreatHuntingModelError("model input must contain HuntEvent observations only")
    return np.asarray([[_feature_value(event, feature) for feature in features] for event in events], dtype=float)


def _sha256(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class SklearnAnomalyPlugin:
    """Deterministic K-Means-distance or Isolation-Forest event detector."""

    def __init__(
        self,
        model_kind: str,
        *,
        feature_schema: tuple[str, ...],
        random_seed: int = 0,
        threshold_quantile: float = 0.95,
        n_clusters: int = 2,
    ) -> None:
        if model_kind not in MODEL_KINDS:
            raise ThreatHuntingModelError("model_kind must be a registered optional model")
        features = tuple(feature_schema)
        if not features or len(set(features)) != len(features):
            raise ThreatHuntingModelError("feature_schema must contain unique features")
        if any(not isinstance(item, str) or not item.strip() for item in features):
            raise ThreatHuntingModelError("feature_schema must contain non-empty strings")
        if isinstance(random_seed, bool) or not isinstance(random_seed, int) or random_seed < 0:
            raise ThreatHuntingModelError("random_seed must be a non-negative integer")
        quantile = _finite_float(threshold_quantile, "threshold_quantile")
        if not 0.5 <= quantile < 1.0:
            raise ThreatHuntingModelError("threshold_quantile must be in [0.5, 1.0)")
        if isinstance(n_clusters, bool) or not isinstance(n_clusters, int) or n_clusters <= 0:
            raise ThreatHuntingModelError("n_clusters must be a positive integer")
        self.model_kind = model_kind
        self.feature_schema = features
        self.random_seed = random_seed
        self.threshold_quantile = quantile
        self.n_clusters = n_clusters
        self._model: object | None = None
        self._mean: np.ndarray | None = None
        self._scale: np.ndarray | None = None
        self._manifest: ModelPluginManifest | None = None

    def fit(
        self,
        events: tuple[HuntEvent, ...],
        *,
        training_data_ids: tuple[str, ...],
    ) -> ModelPluginManifest:
        ordered = tuple(sorted(events, key=lambda event: (event.step, event.event_id)))
        if len(ordered) < 2:
            raise ThreatHuntingModelError("model training requires at least two events")
        training_ids = tuple(training_data_ids)
        if not training_ids:
            raise ThreatHuntingModelError("training_data_ids are required")
        raw = _matrix(ordered, self.feature_schema)
        mean = raw.mean(axis=0)
        scale = raw.std(axis=0)
        scale[scale == 0.0] = 1.0
        matrix = (raw - mean) / scale
        try:
            sklearn_version = metadata.version("scikit-learn")
            if self.model_kind == "kmeans_distance":
                from sklearn.cluster import KMeans

                if self.n_clusters > len(ordered):
                    raise ThreatHuntingModelError("n_clusters exceeds the training sample count")
                model = KMeans(n_clusters=self.n_clusters, random_state=self.random_seed, n_init=10)
                model.fit(matrix)
                scores = np.min(model.transform(matrix), axis=1)
                state: dict[str, object] = {"cluster_centers": model.cluster_centers_.round(12).tolist()}
            else:
                from sklearn.ensemble import IsolationForest

                model = IsolationForest(random_state=self.random_seed, contamination="auto")
                model.fit(matrix)
                scores = -model.decision_function(matrix)
                state = {
                    "estimators": [
                        {
                            "feature": estimator.tree_.feature.tolist(),
                            "threshold": estimator.tree_.threshold.round(12).tolist(),
                        }
                        for estimator in model.estimators_
                    ]
                }
        except ImportError as exc:
            raise ThreatHuntingModelError("scikit-learn is required for this optional plugin") from exc
        threshold = float(np.quantile(scores, self.threshold_quantile))
        preprocessing = {
            "kind": "standard_scaler",
            "mean": mean.round(12).tolist(),
            "scale": scale.round(12).tolist(),
            "missing_numeric": 0.0,
        }
        model_state = {
            "model_kind": self.model_kind,
            "random_seed": self.random_seed,
            "feature_schema": list(self.feature_schema),
            "preprocessing": preprocessing,
            "state": state,
        }
        feature_hash = _sha256({"features": list(self.feature_schema)})
        manifest = ModelPluginManifest(
            plugin_id=f"sklearn_{self.model_kind}_v1",
            model_kind=self.model_kind,
            training_data_ids=training_ids,
            feature_schema=self.feature_schema,
            feature_schema_hash=feature_hash,
            preprocessing=preprocessing,
            model_class=f"{type(model).__module__}.{type(model).__name__}",
            model_version=sklearn_version,
            model_hash=_sha256(model_state),
            random_seed=self.random_seed,
            threshold=threshold,
            calibration={
                "method": "training_score_quantile",
                "quantile": self.threshold_quantile,
                "sample_count": len(ordered),
            },
        )
        self._model = model
        self._mean = mean
        self._scale = scale
        self._manifest = manifest
        return manifest

    def detect(self, events: tuple[HuntEvent, ...]) -> ModelDetectionResult:
        if self._model is None or self._mean is None or self._scale is None or self._manifest is None:
            raise ThreatHuntingModelError("model plugin must be fitted before detection")
        ordered = tuple(sorted(events, key=lambda event: (event.step, event.event_id)))
        matrix = (_matrix(ordered, self.feature_schema) - self._mean) / self._scale
        if self.model_kind == "kmeans_distance":
            scores = np.min(self._model.transform(matrix), axis=1)
        else:
            scores = -self._model.decision_function(matrix)
        threshold = self._manifest.threshold
        maximum = max((float(value) for value in scores), default=threshold)
        denominator = max(maximum - threshold, abs(threshold) * 0.01, 1e-12)
        findings: list[Finding] = []
        event_scores: dict[str, float] = {}
        for event, raw_score in zip(ordered, scores, strict=True):
            raw = float(raw_score)
            event_scores[event.event_id] = raw
            if raw < threshold:
                continue
            score = min(1.0, max(0.0, 0.5 + 0.5 * (raw - threshold) / denominator))
            severity = "high" if score >= 0.85 else "medium"
            finding_id = stable_identifier(
                "finding",
                {
                    "plugin_id": self._manifest.plugin_id,
                    "model_hash": self._manifest.model_hash,
                    "event_id": event.event_id,
                    "threshold": threshold,
                },
            )
            findings.append(
                Finding(
                    schema_version=SCHEMA_VERSION,
                    finding_id=finding_id,
                    recipe_id=f"model:{self._manifest.plugin_id}",
                    recipe_version=self._manifest.plugin_version,
                    severity=severity,
                    score=score,
                    campaign_id=event.campaign_id,
                    actor_id=event.actor_id,
                    start_step=event.step,
                    end_step=event.step,
                    title=f"{self.model_kind} telemetry anomaly",
                    reason=f"model score {raw:.6g} met threshold {threshold:.6g}",
                    evidence_event_ids=(event.event_id,),
                    observed_value=raw,
                    baseline_value=None,
                    threshold=threshold,
                    attributes={
                        "model_plugin_id": self._manifest.plugin_id,
                        "model_hash": self._manifest.model_hash,
                    },
                )
            )
        return ModelDetectionResult(
            manifest=self._manifest,
            findings=tuple(findings),
            event_scores=event_scores,
        )


def compare_detector_findings(
    *,
    simple_findings: tuple[Finding, ...],
    model_findings: tuple[Finding, ...],
    ground_truth: tuple[GroundTruthLabel, ...],
    events: tuple[HuntEvent, ...],
    total_steps: int,
) -> dict[str, object]:
    """Compare rule and model quality plus raw analyst-load components."""

    from .evaluation import ThreatHuntingEvaluator

    evaluator = ThreatHuntingEvaluator()
    simple = evaluator.evaluate(simple_findings, ground_truth, events=events, total_steps=total_steps)
    model = evaluator.evaluate(model_findings, ground_truth, events=events, total_steps=total_steps)
    keys = (
        "precision",
        "recall",
        "f1",
        "finding_count",
        "total_evidence_references",
        "false_positive_finding_count",
        "findings_per_100_steps",
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "simple": {key: simple.metrics[key] for key in keys},
        "model": {key: model.metrics[key] for key in keys},
        "delta": {
            key: float(model.metrics[key] or 0) - float(simple.metrics[key] or 0)
            for key in keys
        },
    }


__all__ = [
    "MODEL_KINDS",
    "MODEL_MANIFEST_RELATIVE_PATH",
    "MODEL_PLUGIN_VERSION",
    "ModelDetectionResult",
    "ModelPluginManifest",
    "SklearnAnomalyPlugin",
    "ThreatHuntingModelError",
    "ThreatHuntingModelPlugin",
    "compare_detector_findings",
]

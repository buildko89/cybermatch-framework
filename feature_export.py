"""CyberMatch feature export and ProfileCore-facing PCA analysis.

This module is intentionally analysis-only. It builds numeric behavior feature
vectors from existing CyberMatch outputs and does not change simulation logic.
"""

from __future__ import annotations

import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence

import numpy as np

from feature_space import FEATURE_NAMES, FeatureSpaceAnalyzer


PROFILECORE_PARENT = Path(__file__).resolve().parent / "external"


@dataclass(frozen=True)
class ProfileCoreConnection:
    connected: bool
    detail: str


@dataclass(frozen=True)
class PCAResult:
    projected_rows: List[Dict[str, object]]
    explained_variance: List[float]
    components: List[Dict[str, float]]
    dominant_dimensions: List[str]
    dominant_component: str
    archetype_distribution: Dict[str, int]
    archetype_count: int
    archetype_concentration: float
    archetype_entropy: float
    profilecore: ProfileCoreConnection


class CyberMatchFeatureExporter:
    """Create CyberMatch behavior feature vectors for downstream analysis."""

    feature_names = FEATURE_NAMES

    def __init__(self) -> None:
        self.analyzer = FeatureSpaceAnalyzer()

    def export_rows(self, rows: Sequence[Mapping[str, object]]) -> List[Dict[str, object]]:
        exported: List[Dict[str, object]] = []
        for index, row in enumerate(rows):
            vector = self.analyzer.build_feature_vector(row)
            exported_row: Dict[str, object] = {
                "row_id": str(row.get("mission_scenario") or row.get("scenario") or f"row_{index + 1}"),
                "true_mission": str(row.get("true_mission") or row.get("attacker_mission") or ""),
                "behavior_profile": str(row.get("behavior_profile") or ""),
            }
            exported_row.update(vector)
            exported.append(exported_row)
        return exported


class ProfileCorePCAAnalyzer:
    """Numerical PCA bridge for CyberMatch behavior archetype discovery."""

    def __init__(self, component_count: int = 3, archetype_count: int = 3) -> None:
        self.component_count = component_count
        self.requested_archetype_count = archetype_count

    def analyze(self, rows: Sequence[Mapping[str, object]]) -> PCAResult:
        exported = CyberMatchFeatureExporter().export_rows(rows)
        if not exported:
            return self._empty_result("no rows")

        matrix = np.asarray(
            [[float(row.get(feature, 0.0)) for feature in FEATURE_NAMES] for row in exported],
            dtype=float,
        )
        projected, ratios, components = self._pca(matrix)
        archetypes = self._assign_archetypes(projected)
        projected_rows: List[Dict[str, object]] = []
        for row, coordinates, archetype in zip(exported, projected, archetypes):
            output = dict(row)
            for idx, value in enumerate(coordinates, start=1):
                output[f"pc{idx}"] = float(value)
            output["archetype"] = archetype
            projected_rows.append(output)

        distribution = self._distribution(archetypes)
        entropy = self._entropy(distribution.values())
        concentration = max(distribution.values()) / len(archetypes) if archetypes else 0.0
        component_maps = [
            {feature: float(component[idx]) for idx, feature in enumerate(FEATURE_NAMES)}
            for component in components
        ]
        dominant_dimensions = [self._dominant_dimension(component) for component in component_maps]
        dominant_component = self._dominant_component(ratios, dominant_dimensions)
        connection = self._publish_to_profilecore(
            projected_rows,
            {
                "explained_variance_ratio": ratios,
                "dominant_dimensions": dominant_dimensions,
                "dominant_component": dominant_component,
                "archetype_distribution": distribution,
            },
        )
        return PCAResult(
            projected_rows=projected_rows,
            explained_variance=ratios,
            components=component_maps,
            dominant_dimensions=dominant_dimensions,
            dominant_component=dominant_component,
            archetype_distribution=distribution,
            archetype_count=len(distribution),
            archetype_concentration=float(concentration),
            archetype_entropy=entropy,
            profilecore=connection,
        )

    def _pca(self, matrix: np.ndarray) -> tuple[np.ndarray, List[float], np.ndarray]:
        if matrix.size == 0 or matrix.shape[0] < 2:
            components = np.eye(min(self.component_count, len(FEATURE_NAMES)), len(FEATURE_NAMES))
            return np.zeros((matrix.shape[0], components.shape[0])), [0.0] * components.shape[0], components

        centered = matrix - np.mean(matrix, axis=0)
        scale = np.std(centered, axis=0)
        scale[scale <= 1e-12] = 1.0
        standardized = centered / scale
        _, singular_values, vt = np.linalg.svd(standardized, full_matrices=False)
        actual_components = min(self.component_count, vt.shape[0])
        components = vt[:actual_components]
        projected = standardized @ components.T
        eigenvalues = (singular_values ** 2) / max(matrix.shape[0] - 1, 1)
        total = float(np.sum(eigenvalues))
        ratios = [float(value / total) if total > 1e-12 else 0.0 for value in eigenvalues[:actual_components]]
        return projected[:, :actual_components], ratios, components

    def _assign_archetypes(self, projected: np.ndarray) -> List[str]:
        if projected.shape[0] == 0:
            return []
        k = min(self.requested_archetype_count, projected.shape[0])
        if k <= 1:
            return ["Archetype-1" for _ in range(projected.shape[0])]
        coordinates = projected[:, : min(2, projected.shape[1])]
        order = np.argsort(coordinates[:, 0])
        centers = coordinates[order[np.linspace(0, len(order) - 1, k, dtype=int)]].copy()
        assignments = np.zeros(coordinates.shape[0], dtype=int)
        for _ in range(20):
            distances = np.linalg.norm(coordinates[:, None, :] - centers[None, :, :], axis=2)
            next_assignments = np.argmin(distances, axis=1)
            if np.array_equal(assignments, next_assignments):
                break
            assignments = next_assignments
            for idx in range(k):
                members = coordinates[assignments == idx]
                if len(members) > 0:
                    centers[idx] = np.mean(members, axis=0)
        used_clusters = {cluster: idx + 1 for idx, cluster in enumerate(sorted(set(int(value) for value in assignments)))}
        return [f"Archetype-{used_clusters[int(value)]}" for value in assignments]

    def _distribution(self, labels: Iterable[str]) -> Dict[str, int]:
        distribution: Dict[str, int] = {}
        for label in labels:
            distribution[label] = distribution.get(label, 0) + 1
        return dict(sorted(distribution.items()))

    def _entropy(self, counts: Iterable[int]) -> float:
        values = [float(count) for count in counts if count > 0]
        total = sum(values)
        if total <= 0.0 or len(values) <= 1:
            return 0.0
        probabilities = [value / total for value in values]
        entropy = -sum(prob * math.log(prob) for prob in probabilities)
        return float(np.clip(entropy / math.log(len(values)), 0.0, 1.0))

    def _dominant_dimension(self, component: Mapping[str, float]) -> str:
        if not component:
            return ""
        return max(component, key=lambda feature: abs(float(component.get(feature, 0.0))))

    def _dominant_component(self, ratios: Sequence[float], dimensions: Sequence[str]) -> str:
        if not ratios:
            return ""
        idx = int(np.argmax(np.asarray(ratios, dtype=float)))
        dimension = dimensions[idx] if idx < len(dimensions) else ""
        return f"PC{idx + 1}:{dimension}" if dimension else f"PC{idx + 1}"

    def _publish_to_profilecore(
        self,
        projected_rows: Sequence[Mapping[str, object]],
        summary: Mapping[str, object],
    ) -> ProfileCoreConnection:
        if not PROFILECORE_PARENT.exists():
            return ProfileCoreConnection(False, "external/profilecore not found")
        if str(PROFILECORE_PARENT) not in sys.path:
            sys.path.insert(0, str(PROFILECORE_PARENT))
        try:
            from profilecore.core.context import ProfileCoreContext  # type: ignore
        except Exception as exc:
            return ProfileCoreConnection(False, f"ProfileCoreContext unavailable: {exc}")
        context = ProfileCoreContext(workspace_dir="output/phase93_profilecore")
        context.set_artifact("pca_summary", dict(summary))
        context.set_artifact("cybermatch_feature_rows", [dict(row) for row in projected_rows])
        return ProfileCoreConnection(True, "ProfileCoreContext artifacts populated")

    def _empty_result(self, detail: str) -> PCAResult:
        return PCAResult(
            projected_rows=[],
            explained_variance=[],
            components=[],
            dominant_dimensions=[],
            dominant_component="",
            archetype_distribution={},
            archetype_count=0,
            archetype_concentration=0.0,
            archetype_entropy=0.0,
            profilecore=ProfileCoreConnection(False, detail),
        )

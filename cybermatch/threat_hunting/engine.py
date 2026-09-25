"""Deterministic execution of validated defender-side hunting recipes."""

from __future__ import annotations

from collections.abc import Iterable
from numbers import Real

from .config import ThreatHuntingRunConfig
from .models import Finding, HuntEvent, SCHEMA_VERSION, stable_identifier
from .operators import (
    OperatorExecutionError,
    OperatorLimitError,
    WorkingRow,
    aggregate_rows,
    derive_rows,
    event_row,
    filter_rows,
    matches_predicate,
    rank_rows,
    row_sort_key,
    sequence_rows,
    validate_regex,
    window_rows,
)
from .recipes import ThreatHuntingRecipe


class ThreatHuntingEngineError(ValueError):
    """Base error for invalid or failed deterministic execution."""


class ThreatHuntingInputError(ThreatHuntingEngineError):
    """Raised when engine input violates the observation contract."""


class ThreatHuntingExecutionError(ThreatHuntingEngineError):
    """Raised when a validated operation cannot process its input."""

    def __init__(self, operation_index: int, operator: str, message: str):
        self.operation_index = operation_index
        self.operator = operator
        super().__init__(f"operation {operation_index} ({operator}) failed: {message}")


class ThreatHuntingLimitError(ThreatHuntingEngineError):
    """Structured fail-closed resource-limit error; results are never truncated."""

    def __init__(self, limit_name: str, limit_value: int, observed: int):
        self.limit_name = limit_name
        self.limit_value = limit_value
        self.observed = observed
        super().__init__(
            f"{limit_name}={limit_value} exceeded by observed value {observed}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "error": "resource_limit_exceeded",
            "limit_name": self.limit_name,
            "limit_value": self.limit_value,
            "observed": self.observed,
        }


class ThreatHuntingEngine:
    """Execute allowlisted operations over HuntEvent observations only."""

    def __init__(self, config: ThreatHuntingRunConfig | None = None):
        self._config = config or ThreatHuntingRunConfig()

    @property
    def config(self) -> ThreatHuntingRunConfig:
        return self._config

    def run(
        self,
        recipe: ThreatHuntingRecipe,
        events: Iterable[HuntEvent],
    ) -> list[Finding]:
        if not isinstance(recipe, ThreatHuntingRecipe):
            raise ThreatHuntingInputError("recipe must be a ThreatHuntingRecipe")
        observations = tuple(events)
        if len(observations) > self._config.max_events:
            raise ThreatHuntingLimitError(
                "max_events", self._config.max_events, len(observations)
            )
        if any(not isinstance(event, HuntEvent) for event in observations):
            raise ThreatHuntingInputError("events must contain HuntEvent observations only")
        event_ids = [event.event_id for event in observations]
        if len(set(event_ids)) != len(event_ids):
            raise ThreatHuntingInputError("event_id values must be unique")

        rows = [event_row(event) for event in observations]
        for row in rows:
            missing = sorted(field for field in recipe.required_fields if field not in row.values)
            if missing:
                raise ThreatHuntingInputError(
                    "event is missing required recipe fields: " + ", ".join(missing)
                )
        rows.sort(key=row_sort_key)
        self._validate_runtime_limits(recipe)

        for index, operation in enumerate(recipe.operations):
            parameters = operation.parameters
            try:
                if operation.operator == "filter":
                    rows = filter_rows(
                        rows,
                        parameters,
                        max_regex_length=self._config.max_regex_length,
                    )
                elif operation.operator == "derive":
                    rows = derive_rows(rows, parameters)
                elif operation.operator == "window":
                    rows = window_rows(rows, parameters)
                elif operation.operator == "aggregate":
                    rows = aggregate_rows(
                        rows,
                        parameters,
                        recipe.group_by,
                        max_groups=self._config.max_groups,
                    )
                elif operation.operator == "rank":
                    rows = rank_rows(
                        rows,
                        parameters,
                        max_groups=self._config.max_groups,
                    )
                elif operation.operator == "sequence":
                    rows = sequence_rows(
                        rows,
                        parameters,
                        recipe.group_by,
                        max_groups=self._config.max_groups,
                        max_findings=self._config.max_findings,
                    )
                else:
                    raise ThreatHuntingExecutionError(
                        index, operation.operator, "operator is not registered"
                    )
            except OperatorLimitError as exc:
                raise ThreatHuntingLimitError(
                    exc.limit_name, exc.limit_value, exc.observed
                ) from exc
            except OperatorExecutionError as exc:
                raise ThreatHuntingExecutionError(index, operation.operator, str(exc)) from exc
            rows.sort(key=row_sort_key)

        return self._findings(recipe, rows)

    def _validate_runtime_limits(self, recipe: ThreatHuntingRecipe) -> None:
        for index, operation in enumerate(recipe.operations):
            parameters = operation.parameters
            if operation.operator == "window":
                size = int(parameters["size_steps"])
                if size > self._config.max_window_steps:
                    raise ThreatHuntingLimitError(
                        "max_window_steps", self._config.max_window_steps, size
                    )
            elif operation.operator == "sequence":
                items = parameters["items"]
                assert isinstance(items, list)
                if len(items) > self._config.max_sequence_length:
                    raise ThreatHuntingLimitError(
                        "max_sequence_length",
                        self._config.max_sequence_length,
                        len(items),
                    )
                span = int(parameters["max_span_steps"])
                if span > self._config.max_window_steps:
                    raise ThreatHuntingLimitError(
                        "max_window_steps", self._config.max_window_steps, span
                    )
                for item in items[1:]:
                    assert isinstance(item, dict)
                    within = item.get("within_steps")
                    if within is not None and int(within) > self._config.max_window_steps:
                        raise ThreatHuntingLimitError(
                            "max_window_steps",
                            self._config.max_window_steps,
                            int(within),
                        )
            elif operation.operator == "filter" and parameters["predicate"] == "regex":
                pattern = str(parameters["value"])
                if len(pattern) > self._config.max_regex_length:
                    raise ThreatHuntingLimitError(
                        "max_regex_length", self._config.max_regex_length, len(pattern)
                    )
                try:
                    validate_regex(pattern, self._config.max_regex_length)
                except OperatorExecutionError as exc:
                    raise ThreatHuntingExecutionError(
                        index, operation.operator, str(exc)
                    ) from exc

    def _findings(
        self,
        recipe: ThreatHuntingRecipe,
        rows: list[WorkingRow],
    ) -> list[Finding]:
        findings: dict[str, Finding] = {}
        condition = recipe.finding.condition
        final_operator = recipe.operations[-1].operator
        final_parameters = recipe.operations[-1].parameters
        observed_field = None
        if final_operator in {"aggregate", "derive"}:
            observed_field = str(final_parameters["as"])
        elif final_operator == "rank":
            observed_field = str(final_parameters["field"])
        elif final_operator == "sequence":
            observed_field = "sequence_count"
        for row in rows:
            if not row.events:
                continue
            if condition is not None and not matches_predicate(
                row.values.get(str(condition["field"])),
                str(condition["predicate"]),
                condition["value"],
                max_regex_length=self._config.max_regex_length,
            ):
                continue
            evidence = tuple(
                event.event_id
                for event in sorted(row.events, key=lambda event: (event.step, event.event_id))
            )
            start_step = min(event.step for event in row.events)
            end_step = max(event.step for event in row.events)
            campaign_id = self._campaign_id(row)
            actor_id = self._actor_id(row)
            group = {
                field: row.values.get(field)
                for field in recipe.group_by
                if isinstance(row.values.get(field), (str, int, float, bool))
                or row.values.get(field) is None
            }
            window_start = row.values.get("window_start")
            window_end = row.values.get("window_end")
            finding_id = stable_identifier(
                "finding",
                {
                    "recipe_id": recipe.recipe_id,
                    "recipe_version": recipe.version,
                    "group": group,
                    "window_start": window_start,
                    "window_end": window_end,
                    "evidence_event_ids": list(evidence),
                },
            )
            observed_value = self._observed_value(row, condition, observed_field)
            threshold = self._threshold(condition)
            reason = self._reason(
                recipe.finding.reason,
                final_operator,
                condition,
                observed_value,
                threshold,
                len(evidence),
            )
            attributes: dict[str, str | int | float | bool | None] = {
                "recipe_hash": recipe.recipe_hash,
                "operator": final_operator,
            }
            if isinstance(window_start, int):
                attributes["window_start"] = window_start
            if isinstance(window_end, int):
                attributes["window_end_exclusive"] = window_end
            finding = Finding(
                schema_version=SCHEMA_VERSION,
                finding_id=finding_id,
                recipe_id=recipe.recipe_id,
                recipe_version=recipe.version,
                severity=recipe.finding.severity,
                score=recipe.finding.score,
                campaign_id=campaign_id,
                actor_id=actor_id,
                start_step=start_step,
                end_step=end_step,
                title=recipe.finding.title,
                reason=reason,
                evidence_event_ids=evidence,
                observed_value=observed_value,
                threshold=threshold,
                attributes=attributes,
            )
            findings[finding_id] = finding
            if len(findings) > self._config.max_findings:
                raise ThreatHuntingLimitError(
                    "max_findings", self._config.max_findings, len(findings)
                )
        return sorted(
            findings.values(),
            key=lambda finding: (
                finding.start_step,
                finding.end_step,
                finding.recipe_id,
                finding.finding_id,
            ),
        )

    @staticmethod
    def _campaign_id(row: WorkingRow) -> str:
        value = row.values.get("campaign_id")
        if isinstance(value, str) and value:
            return value
        campaigns = {event.campaign_id for event in row.events}
        if len(campaigns) != 1:
            raise ThreatHuntingInputError("finding evidence spans multiple campaigns")
        return next(iter(campaigns))

    @staticmethod
    def _actor_id(row: WorkingRow) -> str | None:
        value = row.values.get("actor_id")
        if isinstance(value, str) and value:
            return value
        actors = {event.actor_id for event in row.events}
        return next(iter(actors)) if len(actors) == 1 else None

    @staticmethod
    def _observed_value(
        row: WorkingRow,
        condition: dict[str, object] | None,
        observed_field: str | None,
    ) -> float | None:
        candidates: list[object] = []
        if condition is not None:
            candidates.append(row.values.get(str(condition["field"])))
        if observed_field is not None:
            candidates.append(row.values.get(observed_field))
        for value in candidates:
            if isinstance(value, Real) and not isinstance(value, bool):
                return float(value)
        return None

    @staticmethod
    def _threshold(condition: dict[str, object] | None) -> float | None:
        if condition is None:
            return None
        value = condition["value"]
        if isinstance(value, Real) and not isinstance(value, bool):
            return float(value)
        return None

    @staticmethod
    def _reason(
        base: str,
        operator: str,
        condition: dict[str, object] | None,
        observed_value: float | None,
        threshold: float | None,
        evidence_count: int,
    ) -> str:
        if condition is None:
            return f"{base} operator={operator}; evidence_count={evidence_count}"
        return (
            f"{base} operator={operator}; predicate={condition['predicate']}; "
            f"observed={observed_value}; threshold={threshold}"
        )


__all__ = [
    "ThreatHuntingEngine",
    "ThreatHuntingEngineError",
    "ThreatHuntingExecutionError",
    "ThreatHuntingInputError",
    "ThreatHuntingLimitError",
]

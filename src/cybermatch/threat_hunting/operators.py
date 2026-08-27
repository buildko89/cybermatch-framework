"""Bounded deterministic operators used by the threat-hunting engine."""

from __future__ import annotations

import re
from dataclasses import dataclass
from numbers import Real
from typing import Mapping

from .models import HuntEvent


class OperatorExecutionError(ValueError):
    """Raised when an operation cannot be evaluated safely."""


class OperatorLimitError(OperatorExecutionError):
    def __init__(self, limit_name: str, limit_value: int, observed: int):
        self.limit_name = limit_name
        self.limit_value = limit_value
        self.observed = observed
        super().__init__(
            f"{limit_name}={limit_value} exceeded by observed value {observed}"
        )


@dataclass(frozen=True)
class WorkingRow:
    values: Mapping[str, object]
    events: tuple[HuntEvent, ...]


def event_row(event: HuntEvent) -> WorkingRow:
    values = event.to_dict()
    attributes = values.pop("attributes")
    assert isinstance(attributes, dict)
    for name, value in attributes.items():
        values[f"attributes.{name}"] = value
    return WorkingRow(values=values, events=(event,))


def _value_sort_key(value: object) -> tuple[str, str]:
    return (type(value).__name__, repr(value))


def row_sort_key(row: WorkingRow) -> tuple[object, ...]:
    evidence = tuple((event.step, event.event_id) for event in row.events)
    values = tuple(sorted((key, _value_sort_key(value)) for key, value in row.values.items()))
    return (evidence, values)


def deduplicate_events(rows: list[WorkingRow]) -> tuple[HuntEvent, ...]:
    by_id: dict[str, HuntEvent] = {}
    for row in rows:
        for event in row.events:
            by_id[event.event_id] = event
    return tuple(sorted(by_id.values(), key=lambda event: (event.step, event.event_id)))


def validate_regex(pattern: str, max_length: int) -> re.Pattern[str]:
    if len(pattern) > max_length:
        raise OperatorExecutionError(
            f"regex length {len(pattern)} exceeds max_regex_length={max_length}"
        )
    if "(?" in pattern:
        raise OperatorExecutionError("regex lookaround and extension groups are not allowed")
    if re.search(r"\\[1-9]", pattern):
        raise OperatorExecutionError("regex backreferences are not allowed")
    if re.search(r"\([^)]*[+*][^)]*\)[+*{]", pattern):
        raise OperatorExecutionError("regex nested quantifiers are not allowed")
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise OperatorExecutionError(f"invalid regex: {exc}") from exc


def matches_predicate(
    actual: object,
    predicate: str,
    expected: object,
    *,
    max_regex_length: int,
) -> bool:
    if predicate == "eq":
        return actual == expected
    if predicate == "ne":
        return actual != expected
    if predicate == "in":
        return actual in expected  # type: ignore[operator]
    if predicate == "contains":
        if actual is None:
            return False
        try:
            return expected in actual  # type: ignore[operator]
        except TypeError:
            return False
    if predicate == "regex":
        if not isinstance(actual, str) or not isinstance(expected, str):
            return False
        return validate_regex(expected, max_regex_length).search(actual) is not None
    if (
        isinstance(actual, bool)
        or isinstance(expected, bool)
        or not isinstance(actual, Real)
        or not isinstance(expected, Real)
    ):
        return False
    if predicate == "gt":
        return actual > expected
    if predicate == "gte":
        return actual >= expected
    if predicate == "lt":
        return actual < expected
    if predicate == "lte":
        return actual <= expected
    raise OperatorExecutionError(f"unknown predicate: {predicate}")


def filter_rows(
    rows: list[WorkingRow],
    parameters: Mapping[str, object],
    *,
    max_regex_length: int,
) -> list[WorkingRow]:
    field = str(parameters["field"])
    predicate = str(parameters["predicate"])
    expected = parameters["value"]
    return [
        row
        for row in rows
        if matches_predicate(
            row.values.get(field),
            predicate,
            expected,
            max_regex_length=max_regex_length,
        )
    ]


def derive_rows(rows: list[WorkingRow], parameters: Mapping[str, object]) -> list[WorkingRow]:
    function = str(parameters["function"])
    alias = str(parameters["as"])
    result: list[WorkingRow] = []
    for row in rows:
        if function == "length":
            value = row.values.get(str(parameters["field"]))
            if value is None:
                derived: object = 0
            elif isinstance(value, (str, bytes, tuple, list, set, frozenset, dict)):
                derived = len(value)
            else:
                raise OperatorExecutionError(f"length cannot be applied to {type(value).__name__}")
        elif function == "coalesce":
            fields = parameters["fields"]
            assert isinstance(fields, list)
            derived = next((row.values.get(str(field)) for field in fields if row.values.get(str(field)) is not None), None)
        elif function == "difference":
            fields = parameters["fields"]
            assert isinstance(fields, list)
            left = row.values.get(str(fields[0]))
            right = row.values.get(str(fields[1]))
            if (
                isinstance(left, bool)
                or isinstance(right, bool)
                or not isinstance(left, Real)
                or not isinstance(right, Real)
            ):
                raise OperatorExecutionError("difference requires two numeric values")
            derived = float(left) - float(right)
        else:
            raise OperatorExecutionError(f"unknown derive function: {function}")
        values = dict(row.values)
        values[alias] = derived
        result.append(WorkingRow(values=values, events=row.events))
    return result


def window_rows(rows: list[WorkingRow], parameters: Mapping[str, object]) -> list[WorkingRow]:
    kind = str(parameters["kind"])
    size = int(parameters["size_steps"])
    fixed_start = int(parameters.get("start_step", 0))
    result: list[WorkingRow] = []
    for row in rows:
        step = row.values.get("step")
        if isinstance(step, bool) or not isinstance(step, int):
            raise OperatorExecutionError("window requires an integer step")
        if kind == "fixed":
            start = fixed_start
            if not start <= step < start + size:
                continue
        elif kind == "tumbling":
            start = (step // size) * size
        else:
            raise OperatorExecutionError(f"unknown window kind: {kind}")
        values = dict(row.values)
        values["window_start"] = start
        values["window_end"] = start + size
        result.append(WorkingRow(values=values, events=row.events))
    return result


def _effective_group_fields(rows: list[WorkingRow], group_by: tuple[str, ...]) -> tuple[str, ...]:
    fields: list[str] = []
    if rows and "campaign_id" in rows[0].values:
        fields.append("campaign_id")
    fields.extend(field for field in group_by if field not in fields)
    if rows and "window_start" in rows[0].values:
        fields.extend(field for field in ("window_start", "window_end") if field not in fields)
    return tuple(fields)


def _group_rows(
    rows: list[WorkingRow],
    fields: tuple[str, ...],
    *,
    max_groups: int,
) -> list[tuple[tuple[object, ...], list[WorkingRow]]]:
    groups: dict[tuple[object, ...], list[WorkingRow]] = {}
    for row in rows:
        key = tuple(row.values.get(field) for field in fields)
        groups.setdefault(key, []).append(row)
        if len(groups) > max_groups:
            raise OperatorLimitError("max_groups", max_groups, len(groups))
    return sorted(groups.items(), key=lambda item: tuple(_value_sort_key(value) for value in item[0]))


def _numeric_values(rows: list[WorkingRow], field: str, function: str) -> list[float]:
    values: list[float] = []
    for row in rows:
        value = row.values.get(field)
        if isinstance(value, bool) or not isinstance(value, Real):
            raise OperatorExecutionError(f"aggregate {function} requires numeric field {field!r}")
        values.append(float(value))
    return values


def aggregate_rows(
    rows: list[WorkingRow],
    parameters: Mapping[str, object],
    group_by: tuple[str, ...],
    *,
    max_groups: int,
) -> list[WorkingRow]:
    if not rows:
        return []
    fields = _effective_group_fields(rows, group_by)
    groups = _group_rows(rows, fields, max_groups=max_groups)
    function = str(parameters["function"])
    alias = str(parameters["as"])
    source_field = str(parameters.get("field", ""))
    result: list[WorkingRow] = []
    for key, members in groups:
        if function == "count":
            value: object = len(members)
        elif function in {"sum", "avg", "min", "max"}:
            numeric = _numeric_values(members, source_field, function)
            if function == "sum":
                value = sum(numeric)
            elif function == "avg":
                value = sum(numeric) / len(numeric)
            elif function == "min":
                value = min(numeric)
            else:
                value = max(numeric)
        else:
            distinct = {member.values.get(source_field) for member in members}
            if function == "distinct_count":
                value = len(distinct)
            elif function == "values":
                value = tuple(sorted(distinct, key=_value_sort_key))
            else:
                raise OperatorExecutionError(f"unknown aggregate function: {function}")
        values = {field: item for field, item in zip(fields, key)}
        values[alias] = value
        result.append(WorkingRow(values=values, events=deduplicate_events(members)))
    return result


def rank_rows(
    rows: list[WorkingRow],
    parameters: Mapping[str, object],
    *,
    max_groups: int,
) -> list[WorkingRow]:
    if not rows:
        return []
    partitions = _group_rows(
        rows,
        ("campaign_id",) if "campaign_id" in rows[0].values else (),
        max_groups=max_groups,
    )
    field = str(parameters["field"])
    kind = str(parameters["kind"])
    limit = int(parameters["limit"])
    reverse = kind == "top" or (kind == "sort" and parameters.get("direction", "asc") == "desc")
    result: list[WorkingRow] = []
    for _, members in partitions:
        def rank_key(row: WorkingRow) -> tuple[object, ...]:
            value = row.values.get(field)
            if isinstance(value, bool):
                comparable: tuple[int, object] = (1, int(value))
            elif isinstance(value, Real):
                comparable = (1, float(value))
            elif isinstance(value, str):
                comparable = (2, value)
            elif value is None:
                comparable = (0, "")
            else:
                comparable = (3, repr(value))
            return (*comparable, row_sort_key(row))

        ordered = sorted(
            members,
            key=rank_key,
            reverse=reverse,
        )
        result.extend(ordered[:limit])
    return sorted(result, key=row_sort_key)


def _event_types(item: Mapping[str, object]) -> frozenset[str]:
    raw = item["event_type"]
    if isinstance(raw, str):
        return frozenset({raw})
    assert isinstance(raw, list)
    return frozenset(str(value) for value in raw)


def sequence_rows(
    rows: list[WorkingRow],
    parameters: Mapping[str, object],
    group_by: tuple[str, ...],
    *,
    max_groups: int,
    max_findings: int,
) -> list[WorkingRow]:
    if not rows:
        return []
    if any(len(row.events) != 1 for row in rows):
        raise OperatorExecutionError("sequence must run before aggregation")
    fields = _effective_group_fields(rows, group_by)
    groups = _group_rows(rows, fields, max_groups=max_groups)
    raw_items = parameters["items"]
    assert isinstance(raw_items, list)
    items = [dict(item) for item in raw_items]
    max_span = int(parameters["max_span_steps"])
    overlap = bool(parameters.get("overlap", False))
    result: list[WorkingRow] = []

    for key, members in groups:
        ordered = sorted(members, key=row_sort_key)

        def find_suffix(
            item_index: int,
            previous_index: int,
            first_step: int,
            memo: dict[tuple[int, int], tuple[int, ...] | None],
        ) -> tuple[int, ...] | None:
            state = (item_index, previous_index)
            if state in memo:
                return memo[state]
            item = items[item_index]
            allowed_types = _event_types(item)
            within = item.get("within_steps")
            previous_step = int(ordered[previous_index].values["step"])
            for index in range(previous_index + 1, len(ordered)):
                step = int(ordered[index].values["step"])
                if step - first_step > max_span:
                    break
                if within is not None and step - previous_step > int(within):
                    break
                if ordered[index].values.get("event_type") not in allowed_types:
                    continue
                if item_index == len(items) - 1:
                    memo[state] = (index,)
                    return memo[state]
                suffix = find_suffix(item_index + 1, index, first_step, memo)
                if suffix is not None:
                    memo[state] = (index, *suffix)
                    return memo[state]
            memo[state] = None
            return None

        cursor = 0
        while cursor < len(ordered):
            first_types = _event_types(items[0])
            first_index = next(
                (
                    index
                    for index in range(cursor, len(ordered))
                    if ordered[index].values.get("event_type") in first_types
                ),
                None,
            )
            if first_index is None:
                break
            first_step = int(ordered[first_index].values["step"])
            if len(items) == 1:
                matched = [first_index]
            else:
                suffix = find_suffix(1, first_index, first_step, {})
                matched = [] if suffix is None else [first_index, *suffix]

            if matched:
                matched_rows = [ordered[index] for index in matched]
                values = {field: item for field, item in zip(fields, key)}
                values["sequence_count"] = len(matched_rows)
                result.append(
                    WorkingRow(values=values, events=deduplicate_events(matched_rows))
                )
                if len(result) > max_findings:
                    raise OperatorLimitError(
                        "max_findings", max_findings, len(result)
                    )
                cursor = first_index + 1 if overlap else matched[-1] + 1
            else:
                cursor = first_index + 1
    return sorted(result, key=row_sort_key)


__all__ = [
    "OperatorExecutionError",
    "OperatorLimitError",
    "WorkingRow",
    "aggregate_rows",
    "derive_rows",
    "event_row",
    "filter_rows",
    "matches_predicate",
    "rank_rows",
    "row_sort_key",
    "sequence_rows",
    "validate_regex",
    "window_rows",
]

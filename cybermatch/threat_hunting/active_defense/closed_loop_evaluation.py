"""T3: 4モードのcase/seed対応結果を集計し、paired bootstrap区間を計算する。"""

from __future__ import annotations

import random
from collections.abc import Callable, Mapping, Sequence


def paired_bootstrap_interval(
    pairs: Sequence[tuple[float, float]], *, samples: int = 2_000, confidence: float = 0.95, seed: int = 0,
) -> dict[str, float | int | None]:
    """(比較側, 参照側)の差について、case/seedを組として再標本化する。"""
    if not pairs:
        return {"pair_count": 0, "mean_difference": None, "ci_low": None, "ci_high": None,
                "bootstrap_samples": samples, "confidence": confidence}
    differences = [left - right for left, right in pairs]
    rng = random.Random(seed)
    means = []
    for _ in range(samples):
        draw = [differences[rng.randrange(len(differences))] for _ in differences]
        means.append(sum(draw) / len(draw))
    means.sort()
    tail = (1.0 - confidence) / 2.0
    low = means[min(len(means) - 1, int(tail * len(means)))]
    high = means[min(len(means) - 1, int((1.0 - tail) * len(means)))]
    return {"pair_count": len(pairs), "mean_difference": sum(differences) / len(differences),
            "ci_low": low, "ci_high": high, "bootstrap_samples": samples, "confidence": confidence}


def build_paired_comparisons(
    rows: Sequence[Mapping[str, object]], *, metric: str,
) -> dict[str, dict[str, float | int | None]]:
    """計画§10.1の3比較を、同じseed/profile同士で作る。"""
    index = {(str(row["profile_id"]), int(row["seed"]), str(row["mode_id"])): row for row in rows}
    definitions = {
        "context_search_effect_B1_minus_B0": ("B1_context_open", "B0_internal_open"),
        "response_effect_B3_minus_B1": ("B3_context_closed", "B1_context_open"),
        "context_closed_effect_B3_minus_B2": ("B3_context_closed", "B2_internal_closed"),
    }
    result = {}
    for name, (left_mode, right_mode) in definitions.items():
        pairs = []
        keys = sorted({(profile, seed) for profile, seed, mode in index if mode == left_mode})
        for profile, seed in keys:
            left, right = index.get((profile, seed, left_mode)), index.get((profile, seed, right_mode))
            if left is None or right is None or left.get(metric) is None or right.get(metric) is None:
                continue
            pairs.append((float(left[metric]), float(right[metric])))
        result[name] = paired_bootstrap_interval(pairs)
    return result


def build_logging_hygiene_summary(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, float | int | None]]:
    """mode/profile別recallと、完全profileを分母にしたLHRを返す。"""
    groups: dict[tuple[str, str], list[Mapping[str, object]]] = {}
    for row in rows:
        groups.setdefault((str(row["mode_id"]), str(row["profile_id"])), []).append(row)
    complete_recall: dict[str, float | None] = {}
    for (mode, profile), members in groups.items():
        if profile == "complete":
            started = sum(bool(item["campaign_started"]) for item in members)
            complete_recall[mode] = None if started == 0 else sum(
                bool(item["campaign_started"]) and int(item["finding_count"]) > 0 for item in members) / started
    summary = {}
    for (mode, profile), members in sorted(groups.items()):
        started = sum(bool(item["campaign_started"]) for item in members)
        detected = sum(bool(item["campaign_started"]) and int(item["finding_count"]) > 0 for item in members)
        recall = None if started == 0 else detected / started
        baseline = complete_recall.get(mode)
        lhr = None if recall is None or baseline in (None, 0.0) else recall / baseline
        summary[f"{mode}:{profile}"] = {
            "campaign_count": started, "detected_campaign_count": detected, "end_to_end_recall": recall,
            "complete_profile_recall": baseline, "logging_hygiene_ratio": lhr,
            "recall_difference_from_complete": None if recall is None or baseline is None else recall - baseline,
        }
    return summary


def build_critical_prevention_summary(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, float | int | None]]:
    """同じprofile/seedのB0でcritical到達したcampaignを固定分母にする。"""
    index = {(str(row["profile_id"]), int(row["seed"]), str(row["mode_id"])): row for row in rows}
    result = {}
    for profile in sorted({key[0] for key in index}):
        references = [(seed, row) for (p, seed, mode), row in index.items()
                      if p == profile and mode == "B0_internal_open" and int(row["critical_reach_count"]) > 0]
        for mode in ("B1_context_open", "B2_internal_closed", "B3_context_closed"):
            prevented = sum(int(index[(profile, seed, mode)]["critical_reach_count"]) == 0
                            for seed, _ in references)
            denominator = len(references)
            result[f"{profile}:{mode}"] = {
                "reference_critical_count": denominator, "prevented_count": prevented,
                "critical_reach_prevention_rate": None if denominator == 0 else prevented / denominator,
            }
    return result


__all__ = [
    "build_critical_prevention_summary", "build_logging_hygiene_summary", "build_paired_comparisons",
    "paired_bootstrap_interval",
]

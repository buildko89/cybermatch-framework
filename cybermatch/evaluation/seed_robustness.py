"""Seed-robustness summaries for product comparisons.

Phase6.3 and the Phase8.5 standard benchmark report scores averaged over the
selected seeds. This module re-derives the same scores for every individual
seed and reports their spread (mean, standard deviation, 95% confidence
interval) and how often each candidate ranks first, so a reader can tell
whether a ranking survives a different random realization.
"""

from __future__ import annotations

import csv
import json
import os
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from cybermatch.agentic.statistics import distribution

SEED_ROBUSTNESS_JSON = "seed_robustness.json"
SEED_ROBUSTNESS_CSV = "seed_robustness.csv"
SEED_ROBUSTNESS_REPORT = "SEED_ROBUSTNESS_REPORT.md"
PHASE63_PER_SEED_METRICS = (
    "mission_success_score",
    "campaign_disruption_score",
    "mean_attack_detection_prob",
    "attacker_diversion_score",
    "evaluation_score",
    "product_effectiveness",
)
CSV_COLUMNS = (
    "group",
    "candidate",
    "count",
    "mean",
    "std",
    "ci95_low",
    "ci95_high",
    "min",
    "max",
    "top_share",
)


def phase63_rows_by_seed(output_dir: str, topology_preset: Optional[str]) -> Dict[int, List[Dict[str, object]]]:
    """Rebuild Phase6.3 product x mission rows for each seed of a finished run."""
    from cybermatch.evaluation.runner import _phase63_rows_from_stats

    with open(os.path.join(output_dir, "runs", "summary_runs.json"), "r", encoding="utf-8") as f:
        run_rows = json.load(f)
    by_seed: Dict[int, List[Dict[str, object]]] = {}
    for row in run_rows:
        by_seed.setdefault(int(row["seed"]), []).append(row)
    result: Dict[int, List[Dict[str, object]]] = {}
    for seed, rows in sorted(by_seed.items()):
        stats_rows = [
            {**row, **{f"{metric}_mean": row.get(metric) for metric in PHASE63_PER_SEED_METRICS}}
            for row in rows
        ]
        result[seed], _ = _phase63_rows_from_stats(stats_rows, topology_preset)
    return result


def summarize(
    rows_by_seed: Mapping[int, Sequence[Mapping[str, object]]],
    *,
    candidate_key: str,
    score_key: str,
    group_key: Optional[str] = None,
    exclude_candidates: Iterable[str] = ("baseline",),
) -> Dict[str, object]:
    """Aggregate per-seed scores into spread statistics and first-place shares."""
    excluded = set(exclude_candidates)
    scores: Dict[Tuple[str, str], List[float]] = {}
    winners: Dict[str, List[str]] = {}
    for seed in sorted(rows_by_seed):
        best: Dict[str, Tuple[float, str]] = {}
        for row in rows_by_seed[seed]:
            candidate = str(row.get(candidate_key))
            if candidate in excluded:
                continue
            group = str(row.get(group_key)) if group_key else "overall"
            score = float(row.get(score_key) or 0.0)
            scores.setdefault((group, candidate), []).append(score)
            if group not in best or score > best[group][0]:
                best[group] = (score, candidate)
        for group, (_, candidate) in best.items():
            winners.setdefault(group, []).append(candidate)

    rows: List[Dict[str, object]] = []
    for (group, candidate), values in sorted(scores.items()):
        stats = distribution(values)
        group_winners = winners.get(group, [])
        rows.append(
            {
                "group": group,
                "candidate": candidate,
                **{key: round(float(value), 6) for key, value in stats.items() if key != "count"},
                "count": int(stats["count"]),
                "top_share": round(group_winners.count(candidate) / len(group_winners), 6) if group_winners else 0.0,
            }
        )
    groups: Dict[str, Dict[str, object]] = {}
    for group, group_winners in sorted(winners.items()):
        leader = max(set(group_winners), key=lambda name: (group_winners.count(name), name))
        share = group_winners.count(leader) / len(group_winners)
        groups[group] = {
            "most_frequent_winner": leader,
            "winner_share": round(share, 6),
            "stable": share == 1.0,
        }
    return {
        "seeds": sorted(int(seed) for seed in rows_by_seed),
        "candidate_key": candidate_key,
        "score_key": score_key,
        "group_key": group_key,
        "confidence_interval": "normal approximation, mean +/- 1.96 * std / sqrt(n)",
        "rows": rows,
        "groups": groups,
    }


def write_seed_robustness(
    output_dir: str,
    summary: Mapping[str, object],
    *,
    title: str,
    score_label: str,
    group_label: str,
    label_candidate=str,
    label_group=str,
) -> None:
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, SEED_ROBUSTNESS_JSON), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    with open(os.path.join(output_dir, SEED_ROBUSTNESS_CSV), "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in summary["rows"]:
            writer.writerow({column: row.get(column) for column in CSV_COLUMNS})

    seeds = list(summary["seeds"])
    lines = [
        f"# {title}",
        "",
        "## このレポートで分かること",
        f"seed(乱数の種)を変えて同じ評価を繰り返したとき、{score_label}がどれだけ揺れるか、また有力候補の順位が入れ替わらないかを確認できます。",
        "",
        "## 評価条件",
        f"- seed: `{seeds}`({len(seeds)}件)",
        f"- 信頼区間: 平均 ± 1.96 × 標準偏差 / √n(正規近似)",
        "",
    ]
    if len(seeds) < 2:
        lines += [
            "> seed が1件のため、ばらつきと信頼区間は計算できません。`--seeds 0,1,2,3,4` のように複数指定してください。",
            "",
        ]
    lines += [f"## {group_label}ごとの有力候補の安定性", "", f"| {group_label} | 最も多く1位になった候補 | 1位の割合 | 安定 |", "|---|---|---:|---|"]
    for group, info in summary["groups"].items():
        lines.append(
            f"| {label_group(group)} | {label_candidate(info['most_frequent_winner'])} | "
            f"{float(info['winner_share']):.0%} | {'はい' if info['stable'] else 'いいえ'} |"
        )
    lines += [
        "",
        f"## {score_label}の分布",
        "",
        f"| {group_label} | 候補 | 平均 | 標準偏差 | 95%信頼区間 | 1位の割合 |",
        "|---|---|---:|---:|---|---:|",
    ]
    for row in summary["rows"]:
        lines.append(
            f"| {label_group(row['group'])} | {label_candidate(row['candidate'])} | {row['mean']:.3f} | {row['std']:.3f} | "
            f"[{row['ci95_low']:.3f}, {row['ci95_high']:.3f}] | {row['top_share']:.0%} |"
        )
    lines += [
        "",
        "## 結果の読み方",
        "- **1位の割合が100%**: どの seed でも同じ候補が1位でした。この条件での結論は seed に左右されにくいと言えます。",
        "- **1位の割合が100%未満**: seed によって1位が入れ替わりました。候補間の差は偶然の揺れと同程度の可能性があります。",
        "- **信頼区間が重なる**: 2つの候補の差は、この seed 数では明確とは言えません。seed を増やすと判断しやすくなります。",
        "",
        "## 注意事項",
        "このばらつきは、シミュレーション内の確率的な事象(検知・攻撃成功など)に由来するものです。モデル仮定・製品プロファイル・トポロジの違いによる不確かさは含みません。",
        "",
    ]
    with open(os.path.join(output_dir, SEED_ROBUSTNESS_REPORT), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_phase63_seed_robustness(output_dir: str, topology_preset: Optional[str]) -> Dict[str, object]:
    """Write per-seed spread for a finished Phase6.3 run in ``output_dir``."""
    from cybermatch.evaluation.runner import _report_mission_label, _report_product_label

    rows_by_seed = phase63_rows_by_seed(output_dir, topology_preset)
    summary = summarize(
        rows_by_seed,
        candidate_key="profile_id",
        score_key="mission_effectiveness",
        group_key="mission_name",
    )
    write_seed_robustness(
        output_dir,
        summary,
        title="seed 頑健性レポート(製品×攻撃目的)",
        score_label="比較スコア",
        group_label="攻撃者の目的",
        label_candidate=_report_product_label,
        label_group=_report_mission_label,
    )
    return summary


def write_phase63_per_seed_summaries(output_dir: str, topology_preset: Optional[str]) -> Dict[int, str]:
    """Write one Phase6.3-compatible summary per seed below ``output_dir/seeds``.

    The files use the same ``{"rows": [...]}`` layout as
    ``mission_product_summary.json`` so the Phase8.x suites can load them as a
    baseline.
    """
    paths: Dict[int, str] = {}
    for seed, rows in phase63_rows_by_seed(output_dir, topology_preset).items():
        seed_dir = os.path.join(output_dir, "seeds", f"seed_{seed}")
        os.makedirs(seed_dir, exist_ok=True)
        path = os.path.join(seed_dir, "mission_product_summary.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"rows": rows}, f, ensure_ascii=False, indent=2)
        paths[seed] = path
    return paths


__all__ = [
    "SEED_ROBUSTNESS_CSV",
    "SEED_ROBUSTNESS_JSON",
    "SEED_ROBUSTNESS_REPORT",
    "phase63_rows_by_seed",
    "summarize",
    "write_phase63_per_seed_summaries",
    "write_phase63_seed_robustness",
    "write_seed_robustness",
]

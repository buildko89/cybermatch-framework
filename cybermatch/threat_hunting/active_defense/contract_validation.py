"""T2契約で共有する厳格な値検査。JSON Schemaと同じ制約をPython側でも適用する。"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence

ACTIVE_DEFENSE_CONTRACT_VERSION = "1.0"
BASIS_POINT_MAX = 10_000

# IDやsource名へ評価labelを埋め込むと、opaque IDからtruthを復元できてしまう。
_LABEL_TOKENS = ("malicious", "benign", "true_label", "ground_truth", "oracle", "gold_label")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,255}\Z")
_ENDPOINT = re.compile(r"([a-z][a-z0-9+.-]{0,15})://([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)*):([0-9]{1,5})\Z")
_DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+\Z")


class ActiveDefenseContractError(ValueError):
    """T2の観測・相関・仮説・scheduler契約に違反した入力。"""


def exact_fields(payload: object, expected: set[str], name: str) -> Mapping[str, object]:
    """未知fieldと必須field不足を同時に拒否する。任意項目も明示nullで書く。"""
    if not isinstance(payload, Mapping):
        raise ActiveDefenseContractError(f"{name}: JSONオブジェクトが必要です")
    keys = set(payload)
    if keys != expected:
        missing = sorted(expected - keys)
        unknown = sorted(str(key) for key in keys - expected)
        raise ActiveDefenseContractError(f"{name}: 必須項目不足={missing} 未知項目={unknown}")
    return payload


def version(value: object, name: str) -> str:
    if value != ACTIVE_DEFENSE_CONTRACT_VERSION:
        raise ActiveDefenseContractError(f"{name}: 未対応のschema_versionです")
    return ACTIVE_DEFENSE_CONTRACT_VERSION


def ref(value: object, name: str) -> str:
    """空白・制御文字を含まない参照ID。評価labelの埋込みも拒否する。"""
    if not isinstance(value, str) or _REF.fullmatch(value) is None:
        raise ActiveDefenseContractError(f"{name}: 空白を含まない256文字以内の参照IDが必要です")
    lowered = value.lower()
    if any(token in lowered for token in _LABEL_TOKENS):
        raise ActiveDefenseContractError(f"{name}: IDへ評価labelを埋め込めません")
    return value


def optional_ref(value: object, name: str) -> str | None:
    return None if value is None else ref(value, name)


def refs(value: object, name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    """wire上で重複なし昇順の配列だけを受け付ける（入力順序でhashを変えない）。"""
    if not isinstance(value, (list, tuple)):
        raise ActiveDefenseContractError(f"{name}: 文字列配列が必要です")
    items = tuple(ref(item, name) for item in value)
    if list(items) != sorted(set(items)):
        raise ActiveDefenseContractError(f"{name}: 重複なしの昇順で指定してください")
    if not items and not allow_empty:
        raise ActiveDefenseContractError(f"{name}: 空にできません")
    return items


def step(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ActiveDefenseContractError(f"{name}: 非負整数が必要です")
    return value


def positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ActiveDefenseContractError(f"{name}: 正の整数が必要です")
    return value


def basis_point(value: object, name: str) -> int:
    """0〜10,000の整数basis point。bool・浮動小数・NaNは受理しない。"""
    if isinstance(value, float) and not math.isfinite(value):
        raise ActiveDefenseContractError(f"{name}: 有限の整数が必要です")
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= BASIS_POINT_MAX:
        raise ActiveDefenseContractError(f"{name}: 0〜10000の整数basis pointが必要です")
    return value


def optional_basis_point(value: object, name: str) -> int | None:
    return None if value is None else basis_point(value, name)


def choice(value: object, allowed: Sequence[str], name: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ActiveDefenseContractError(f"{name}: {', '.join(allowed)} のいずれかが必要です")
    return value


def optional_choice(value: object, allowed: Sequence[str], name: str) -> str | None:
    return None if value is None else choice(value, allowed, name)


def endpoint_ref(value: object, name: str) -> str:
    """正規化済み`scheme://host:port`だけを受理する。暗黙の正規化で別endpointを合流させない。"""
    if not isinstance(value, str) or _ENDPOINT.fullmatch(value) is None:
        raise ActiveDefenseContractError(f"{name}: 小文字の`scheme://host:port`形式が必要です")
    port = int(value.rsplit(":", 1)[1])
    if not 1 <= port <= 65_535 or str(port) != value.rsplit(":", 1)[1]:
        raise ActiveDefenseContractError(f"{name}: portは先頭0なしの1〜65535が必要です")
    return value


def endpoint_host(value: str) -> str:
    return value.split("://", 1)[1].rsplit(":", 1)[0]


def domain_ref(value: object, name: str) -> str:
    if not isinstance(value, str) or _DOMAIN.fullmatch(value) is None:
        raise ActiveDefenseContractError(f"{name}: 末尾dotなしの小文字domainが必要です")
    return value


def step_window(observed_step: int, available_step: int, valid_until_step: int, name: str) -> None:
    """発生→利用可能→失効の順序。到着時点で失効済みでも記録自体は保持できる。"""
    if available_step < observed_step:
        raise ActiveDefenseContractError(f"{name}: available_stepはobserved_step以上が必要です")
    if valid_until_step <= observed_step:
        raise ActiveDefenseContractError(f"{name}: valid_until_stepはobserved_stepより後が必要です")


__all__ = [
    "ACTIVE_DEFENSE_CONTRACT_VERSION", "BASIS_POINT_MAX", "ActiveDefenseContractError",
    "basis_point", "choice", "domain_ref", "endpoint_host", "endpoint_ref", "exact_fields",
    "optional_basis_point", "optional_choice", "optional_ref", "positive_int", "ref", "refs",
    "step", "step_window", "version",
]

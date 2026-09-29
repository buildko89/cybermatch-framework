"""証跡・観測成果物へ平文PIIやsecretを出さないための最小検査。"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence


class SensitiveDataHygieneError(ValueError):
    """成果物に保存してはいけないfield名または値の形式を検出した。"""


_FORBIDDEN_FIELD_TOKENS = frozenset({
    "password", "credential_value", "secret", "access_token", "refresh_token",
    "private_key", "raw_identity",
})
_EMAIL = re.compile(r"(?i)^[^\s@]+@[^\s@]+\.[^\s@]+$")
_PEM = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")
_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")


def assert_hygienic_payload(payload: object) -> None:
    """JSON相当のpayloadを再帰検査し、値を例外へ出さずに拒否する。

    これは検出器であり、PIIを完全に識別・削除する匿名化器ではない。失敗時は
    payloadをログ出力せず、入力adapterまたは成果物writerで処理を停止する。
    """
    _scan(payload, "$")


def _scan(value: object, path: str) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise SensitiveDataHygieneError(f"{path}: field名が文字列ではありません")
            lowered = key.lower()
            if any(token in lowered for token in _FORBIDDEN_FIELD_TOKENS):
                raise SensitiveDataHygieneError(f"{path}.{key}: 保存禁止fieldです")
            _scan(nested, f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, nested in enumerate(value):
            _scan(nested, f"{path}[{index}]")
        return
    if isinstance(value, str):
        if _EMAIL.fullmatch(value) or _PEM.search(value) or _AWS_ACCESS_KEY.search(value):
            raise SensitiveDataHygieneError(f"{path}: 保存禁止の値形式です")


__all__ = ["SensitiveDataHygieneError", "assert_hygienic_payload"]

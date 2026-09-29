"""Agent Skills評価用の、状態を外部へ出さない模擬tool境界。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MockToolRequest:
    request_id: str
    tenant_id: str
    agent_ref: str
    operation: str
    resource_ref: str
    purpose_ref: str

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value.strip() for value in self.__dict__.values()):
            raise ValueError("模擬tool requestの全項目に空でない文字列が必要です")


@dataclass(frozen=True)
class MockToolReceipt:
    request_id: str
    status: str
    reason_code: str

    def to_dict(self) -> dict[str, str]:
        return self.__dict__.copy()


class MockToolBoundary:
    """tenant別allowlistに完全一致する操作だけを模擬的に許可する。"""

    def __init__(self, allowed: set[tuple[str, str, str]]):
        self._allowed = frozenset(allowed)

    def evaluate(self, request: MockToolRequest) -> MockToolReceipt:
        key = (request.tenant_id, request.operation, request.resource_ref)
        if key in self._allowed:
            return MockToolReceipt(request.request_id, "allowed", "allowlist_match")
        return MockToolReceipt(request.request_id, "blocked", "allowlist_miss")


__all__ = ["MockToolBoundary", "MockToolReceipt", "MockToolRequest"]

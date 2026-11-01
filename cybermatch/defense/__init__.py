"""CyberMatch defense modules and adapters."""
from .proxy_gateway import LabProxyGateway
from .proxy_adapter import (
    ProxyEnforcementAdapter,
    ExecutionGateError,
    RevisionConflictError,
    ReadBackMismatchError,
    EffectConfirmationError,
)
from .shadow_evaluator import (
    ShadowEvaluator,
    ShadowEvaluationResult,
    TransactionRecord,
    generate_golden_replay_dataset,
)

__all__ = [
    "LabProxyGateway",
    "ProxyEnforcementAdapter",
    "ExecutionGateError",
    "RevisionConflictError",
    "ReadBackMismatchError",
    "EffectConfirmationError",
    "ShadowEvaluator",
    "ShadowEvaluationResult",
    "TransactionRecord",
    "generate_golden_replay_dataset",
]

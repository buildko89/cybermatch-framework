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
from .mitigation_pipeline import MitigationPipelineOrchestrator
from .deception import HoneyPatchResponder
from .deception_evaluator import (
    Phase4DeceptionBenchmark,
    AdaptiveAttackEpisodeSimulator,
    ConditionBenchmarkResult,
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
    "MitigationPipelineOrchestrator",
    "HoneyPatchResponder",
    "Phase4DeceptionBenchmark",
    "AdaptiveAttackEpisodeSimulator",
    "ConditionBenchmarkResult",
]

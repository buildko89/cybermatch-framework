"""CyberMatch defense modules and adapters."""
from .zerotrust_evaluator import ZeroTrustEvaluator
from .secure_coding_evaluator import SecureCodingEvaluator
from .genai_defense_evaluator import GenAIDefenseEvaluator
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
    "GenAIDefenseEvaluator",
    "SecureCodingEvaluator",
    "ZeroTrustEvaluator",
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

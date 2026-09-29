"""CTI・ASM・内部ログを統合する文脈ハンティング（統合計画T2〜T3）。

T2の範囲: 観測契約、as-of選択、相関規則v1、priority policy v1、仮説template、
scheduler、FindingTrace、決定論的runner。
T3の範囲: ログ健全性変換、状態付き模擬世界、対象限定対処sink、4モード比較評価。
"""

from .active_defense_evaluation_report import (
    render_active_defense_evaluation_report, write_active_defense_evaluation_outputs,
)
from .active_defense_evaluation_runner import (
    MODES, ActiveDefenseEvaluationInputs, ActiveDefenseEvaluationResult, ActiveDefenseEvaluationRunner,
    ActiveDefenseEvaluationSpec, ExposureTruth, ModeEvaluationResult, load_active_defense_evaluation_inputs,
)

from .as_of_selection import AsOfView, select_as_of, validate_supersession
from .context_hunting_report import RUNNER_NAME, render_report, write_context_hunting_outputs
from .context_hunting_runner import (
    BindingExecution, ContextHuntingInputs, ContextHuntingResult, ContextHuntingRunSpec,
    ContextHuntingRunner, INTERNAL_TELEMETRY_KINDS, build_context_hunting_inputs, load_context_hunting_inputs,
    parse_observation_fixture,
)
from .contract_validation import ACTIVE_DEFENSE_CONTRACT_VERSION, ActiveDefenseContractError
from .exposure_correlation import ExposureCorrelator, ExposureMatch, MATCH_KINDS, MATCH_STATUSES
from .exposure_observations import (
    ASMAssetObservation, CTIObservation, ObservedAssetBinding, VulnerabilityObservation,
)
from .finding_trace import FindingTrace, FindingTraceLedger
from .hypothesis_scheduler import (
    NOT_EVALUABLE_MISSING_FIELDS, HypothesisScheduler, SchedulerDecision, SchedulerPolicy, SelectedBinding,
)
from .hypothesis_templates import (
    HypothesisGenerator, HypothesisSpec, HypothesisTemplate, HypothesisTemplateCatalog, RecipeBinding,
)
from .priority_policy import PRIORITY_COMPONENTS, PriorityPolicy, PriorityScore
from .logging_hygiene import (
    HygieneTransformResult, LoggingHygieneConfig, LoggingHygieneTransform, TelemetryFamilyRule,
)
from .response_action_sink import FindingAuthorization, StatefulResponseActionSink
from .stateful_mock_world import OperationOutcome, PotentialOperation, StatefulMockWorld
from .attacker_consequence_adapter import AttackerConsequenceAdapter, ObservableDefenderConsequence
from .hypothesis_pilot import (
    DeterministicHypothesisSelectionGateway, build_hypothesis_pilot_view,
    run_hypothesis_pilot_shadow, write_hypothesis_pilot_shadow,
)
from .tokenized_replay_adapter import ReplayDataQualityReport, TokenizedReplayAdapter, TokenizedReplaySnapshot
from .tokenized_replay_report import render_tokenized_replay_report, write_tokenized_replay_outputs
from .tokenized_replay_runner import (
    TokenizedReplayInputs, TokenizedReplayResult, TokenizedReplayRunSpec, TokenizedReplayRunner,
    load_tokenized_replay_inputs,
)

__all__ = [
    "ACTIVE_DEFENSE_CONTRACT_VERSION", "ASMAssetObservation", "ActiveDefenseContractError",
    "AttackerConsequenceAdapter",
    "ActiveDefenseEvaluationInputs", "ActiveDefenseEvaluationResult", "ActiveDefenseEvaluationRunner",
    "ActiveDefenseEvaluationSpec", "AsOfView", "ExposureTruth",
    "BindingExecution", "CTIObservation", "ContextHuntingInputs", "ContextHuntingResult",
    "ContextHuntingRunSpec", "ContextHuntingRunner", "ExposureCorrelator", "ExposureMatch", "FindingTrace",
    "DeterministicHypothesisSelectionGateway", "FindingAuthorization", "FindingTraceLedger",
    "HygieneTransformResult", "HypothesisGenerator",
    "HypothesisScheduler", "HypothesisSpec", "HypothesisTemplate",
    "HypothesisTemplateCatalog", "INTERNAL_TELEMETRY_KINDS", "MATCH_KINDS", "MATCH_STATUSES",
    "LoggingHygieneConfig", "LoggingHygieneTransform", "MODES", "ModeEvaluationResult",
    "NOT_EVALUABLE_MISSING_FIELDS", "ObservedAssetBinding", "OperationOutcome", "PRIORITY_COMPONENTS",
    "ObservableDefenderConsequence", "PotentialOperation", "PriorityPolicy", "ReplayDataQualityReport",
    "PriorityScore", "RUNNER_NAME", "RecipeBinding", "SchedulerDecision", "SchedulerPolicy", "SelectedBinding",
    "StatefulMockWorld", "StatefulResponseActionSink", "TelemetryFamilyRule", "TokenizedReplayAdapter",
    "TokenizedReplayInputs", "TokenizedReplayResult", "TokenizedReplayRunSpec", "TokenizedReplayRunner",
    "TokenizedReplaySnapshot", "VulnerabilityObservation", "build_hypothesis_pilot_view",
    "build_context_hunting_inputs", "load_active_defense_evaluation_inputs", "load_context_hunting_inputs",
    "load_tokenized_replay_inputs", "render_tokenized_replay_report", "run_hypothesis_pilot_shadow",
    "parse_observation_fixture", "render_report",
    "render_active_defense_evaluation_report", "select_as_of", "validate_supersession",
    "write_active_defense_evaluation_outputs", "write_context_hunting_outputs",
    "write_hypothesis_pilot_shadow", "write_tokenized_replay_outputs",
]

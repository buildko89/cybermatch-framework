"""Public API for CyberMatch analysis-guided semantic fuzzing."""

from .analysis_guidance import GUIDANCE_WEIGHTS, score_analysis_guidance
from .artifacts import (
    CAMPAIGN_CSV_FILENAME,
    CAMPAIGN_MANIFEST_FILENAME,
    CAMPAIGN_REPORT_FILENAME,
    CAMPAIGN_SUMMARY_FILENAME,
    FUZZING_ARTIFACT_FORMAT_VERSION,
    FuzzArtifactError,
    FuzzArtifactExistsError,
    FuzzArtifactWriter,
    load_fuzz_campaign,
)
from .corpus import FuzzCorpusError, generate_cases, load_seed_input
from .constraints import FORBIDDEN_OBSERVATION_FIELDS, FuzzConstraintError, validate_semantic_events
from .external import (
    AllowlistedCommandTransport,
    ExternalCodec,
    ExternalInfrastructureError,
    ExternalMappingError,
    ExternalProtocolError,
    ExternalSUTMapping,
    ExternalTransport,
    MockExternalTransport,
    load_external_mapping,
)
from .minimizer import minimize_events
from .models import (
    ExecutionLimits,
    FUZZING_SCHEMA_VERSION,
    FuzzCase,
    MutationRecord,
    OracleResult,
    SeedInput,
    TargetResult,
)
from .mutators import MutationError, apply_mutation, events_hash, reidentify_events
from .oracles import evaluate_oracles, is_interesting
from .runner import replay_case, run_campaign
from .scheduler import schedule_cases, semantic_signature
from .specs import (
    FuzzCampaignSpec,
    FuzzSpecError,
    FuzzTargetSpec,
    MutatorSpec,
    load_campaign_spec,
    validate_campaign_spec,
)
from .targets import (
    ExternalSUTTarget,
    FuzzTarget,
    PairedTargetResult,
    TargetManifest,
    ThreatHuntingClosedLoopTarget,
    ThreatHuntingEngineTarget,
)


__all__ = [
    "CAMPAIGN_CSV_FILENAME",
    "CAMPAIGN_MANIFEST_FILENAME",
    "CAMPAIGN_REPORT_FILENAME",
    "CAMPAIGN_SUMMARY_FILENAME",
    "ExecutionLimits",
    "ExternalCodec",
    "ExternalInfrastructureError",
    "ExternalMappingError",
    "ExternalProtocolError",
    "ExternalSUTMapping",
    "ExternalSUTTarget",
    "ExternalTransport",
    "FUZZING_ARTIFACT_FORMAT_VERSION",
    "FUZZING_SCHEMA_VERSION",
    "FuzzArtifactError",
    "FuzzArtifactExistsError",
    "FuzzArtifactWriter",
    "FuzzCampaignSpec",
    "FuzzCase",
    "FuzzConstraintError",
    "FuzzCorpusError",
    "FuzzSpecError",
    "FuzzTarget",
    "FuzzTargetSpec",
    "GUIDANCE_WEIGHTS",
    "FORBIDDEN_OBSERVATION_FIELDS",
    "MutationError",
    "MockExternalTransport",
    "MutationRecord",
    "MutatorSpec",
    "OracleResult",
    "PairedTargetResult",
    "SeedInput",
    "TargetManifest",
    "TargetResult",
    "ThreatHuntingEngineTarget",
    "ThreatHuntingClosedLoopTarget",
    "apply_mutation",
    "AllowlistedCommandTransport",
    "evaluate_oracles",
    "events_hash",
    "generate_cases",
    "is_interesting",
    "load_campaign_spec",
    "load_external_mapping",
    "load_fuzz_campaign",
    "load_seed_input",
    "minimize_events",
    "reidentify_events",
    "replay_case",
    "run_campaign",
    "schedule_cases",
    "score_analysis_guidance",
    "semantic_signature",
    "validate_campaign_spec",
    "validate_semantic_events",
]

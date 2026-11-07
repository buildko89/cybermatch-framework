"""Conservative, cumulative CISA-inspired checklist scoring, not certification.

Configuration uses five top-level pillar mappings. Boolean controls must be actual
bools. Missing evidence never grants credit. The YAML profile mirrors CHECKLISTS.
Containment coefficients are scenario assumptions, not measured probabilities.
"""

from collections.abc import Mapping

from cybermatch.models.zerotrust import (
    MFABypassVector, MFAMitigation, MaturityLevel, PillarAssessment,
    ZeroTrustAssessmentResult, ZTPillar,
)


# Each tuple describes Initial, Advanced, Optimal; requirements are cumulative.
CHECKLISTS = {
    ZTPillar.IDENTITY: (("mfa_enabled",), ("fido2_passkey", "conditional_access", "sms_fallback_disabled"),
                        ("continuous_verification", "just_in_time_access")),
    ZTPillar.DEVICE: (("mdm_managed",), ("edr_enabled", "device_compliance_required"),
                      ("continuous_monitoring", "automated_remediation")),
    ZTPillar.NETWORK: (("segmentation",), ("microsegmentation", "encrypted_traffic"),
                       ("dynamic_policy", "automated_response")),
    ZTPillar.APPLICATION: (("sso_enabled",), ("least_privilege", "workload_identity"),
                           ("continuous_authorization", "automated_lifecycle")),
    ZTPillar.DATA: (("inventory",), ("classification", "encryption_at_rest", "dlp_enabled"),
                    ("dynamic_access", "automated_classification")),
}
CONTAINMENT = {1: 0.1, 2: 0.35, 3: 0.70, 4: 0.95}
MFA_TYPES = {"none", "sms", "totp", "push", "fido2", "passkey"}
AUTH_KEYS = {"mfa_type", "fido2_passkey", "number_matching", "token_binding_cae",
             "token_binding", "device_compliance_required"}


def _validate_keys(config: Mapping, allowed: set[str], description: str) -> None:
    for key in config:
        if key not in allowed:
            raise ValueError(f"unknown {description}: {key}")


def _mapping(value: object, name: str) -> Mapping:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    return value


def _flag(config: Mapping, key: str) -> bool:
    value = config.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _auth(config: Mapping) -> tuple[str, MFAMitigation]:
    _validate_keys(config, AUTH_KEYS, "authentication key")
    method = config.get("mfa_type", "none")
    if not isinstance(method, str) or method.lower() not in MFA_TYPES:
        raise ValueError(f"mfa_type must be one of {sorted(MFA_TYPES)}")
    method = method.lower()
    flags = {key: _flag(config, key) for key in AUTH_KEYS - {"mfa_type"}}
    return method, MFAMitigation(
        fido2_passkey=flags["fido2_passkey"] or method in {"fido2", "passkey"},
        number_matching=flags["number_matching"],
        token_binding_cae=flags["token_binding_cae"] or flags["token_binding"],
        device_compliance_required=flags["device_compliance_required"],
    )


class ZeroTrustEvaluator:
    def evaluate_cisa_maturity(self, env_config: dict) -> ZeroTrustAssessmentResult:
        """Score (level - 1) / 3, then average all five pillars equally."""
        env = _mapping(env_config, "env_config")
        _validate_keys(env, {p.value for p in ZTPillar}, "pillar")
        pillars = {}
        for pillar, stages in CHECKLISTS.items():
            config = dict(_mapping(env.get(pillar.value, {}), pillar.value))
            allowed = {key for requirements in stages for key in requirements}
            if pillar == ZTPillar.IDENTITY:
                allowed |= AUTH_KEYS
            _validate_keys(config, allowed, "configuration key")
            for key in config.keys() - {"mfa_type"}:
                _flag(config, key)
            if pillar == ZTPillar.IDENTITY:
                method, mitigation = _auth({key: value for key, value in config.items() if key in AUTH_KEYS})
                config["mfa_enabled"] = method != "none" or mitigation.fido2_passkey
                config["fido2_passkey"] = mitigation.fido2_passkey
                config["sms_fallback_disabled"] = method != "sms"
            level = MaturityLevel.TRADITIONAL
            unmet = []
            eligible = True
            for stage, requirements in enumerate(stages, start=2):
                missing = [key for key in requirements if not _flag(config, key)]
                unmet.extend(f"{MaturityLevel(stage).name.lower()}.{key}" for key in missing)
                eligible = eligible and not missing
                if eligible:
                    level = MaturityLevel(stage)
            pillars[pillar] = PillarAssessment(pillar, level, (level - 1) / 3, tuple(unmet))
        return ZeroTrustAssessmentResult(
            sum(item.score for item in pillars.values()) / 5,
            pillars,
            sum(CONTAINMENT[item.level] for item in pillars.values()) / 5,
        )

    def evaluate_mfa_resilience(self, auth_config: dict) -> dict:
        """Assess the configured method, with no implicit fallback methods.

        token_binding_cae asserts effective replay-resistant token binding with
        session reevaluation. CAE alone does not prevent stolen-token replay.
        FIDO2 resists AiTM authentication phishing, not arbitrary cookie theft.
        """
        method, mitigation = _auth(_mapping(auth_config, "auth_config"))
        vulnerabilities = {
            MFABypassVector.SIM_SWAP: method == "sms",
            MFABypassVector.PUSH_BOMBING: method == "push" and not mitigation.number_matching,
            MFABypassVector.AITM_TOKEN_THEFT: not mitigation.token_binding_cae,
        }
        recommendations = {
            MFABypassVector.SIM_SWAP: "Replace SMS (including recovery/fallback) with FIDO2/passkeys.",
            MFABypassVector.PUSH_BOMBING: "Enable number matching, prompt throttling, and FIDO2/passkeys.",
            MFABypassVector.AITM_TOKEN_THEFT: "Use FIDO2/passkeys and device-bound tokens with continuous session reevaluation; CAE alone is insufficient.",
        }
        return {
            vector: {"vulnerable": vulnerable,
                     "recommendations": [recommendations[vector]] if vulnerable else []}
            for vector, vulnerable in vulnerabilities.items()
        }

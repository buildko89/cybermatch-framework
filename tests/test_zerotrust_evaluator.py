"""Phase 5 scoring, authentication resilience, and asset consistency."""

from pathlib import Path
from dataclasses import FrozenInstanceError

import pytest
import yaml

from cybermatch.defense import ZeroTrustEvaluator
from cybermatch.defense.zerotrust_evaluator import CHECKLISTS, CONTAINMENT
from cybermatch.models.zerotrust import (
    MFABypassVector, MaturityLevel, PillarAssessment, ZeroTrustAssessmentResult, ZTPillar,
)


ROOT = Path(__file__).resolve().parents[1]


def environment(stage):
    config = {
        pillar.value: {key: True for keys in stages[:stage - 1] for key in keys}
        for pillar, stages in CHECKLISTS.items()
    }
    config['identity']['mfa_type'] = 'fido2' if stage >= 3 else 'sms' if stage == 2 else 'none'
    return config


def test_cisa_maturity_traditional_vs_optimal():
    evaluator = ZeroTrustEvaluator()
    traditional = evaluator.evaluate_cisa_maturity({})
    optimal = evaluator.evaluate_cisa_maturity(environment(4))
    assert traditional.overall_score == 0.0
    assert traditional.containment_factor == pytest.approx(0.1)
    assert optimal.overall_score == 1.0
    assert optimal.containment_factor == pytest.approx(0.95)
    assert all(p.level == MaturityLevel.TRADITIONAL for p in traditional.pillars.values())
    assert all(p.level == MaturityLevel.OPTIMAL for p in optimal.pillars.values())
    assert all(not p.unmet_requirements for p in optimal.pillars.values())


def test_mfa_bypass_resilience_evaluation():
    evaluate = ZeroTrustEvaluator().evaluate_mfa_resilience
    sms = evaluate({'mfa_type': 'SMS'})
    assert sms[MFABypassVector.SIM_SWAP]['vulnerable']
    assert sms[MFABypassVector.SIM_SWAP]['recommendations']
    assert evaluate({'mfa_type': 'push'})['push_bombing']['vulnerable']
    assert not evaluate({'mfa_type': 'push', 'number_matching': True})['push_bombing']['vulnerable']
    assert evaluate({'mfa_type': 'totp'})['aitm_token_theft']['vulnerable']
    assert evaluate({'mfa_type': 'fido2'})['aitm_token_theft']['vulnerable']
    assert not evaluate({'mfa_type': 'totp', 'token_binding_cae': True})['aitm_token_theft']['vulnerable']
    protected = evaluate({'mfa_type': 'FIDO2', 'token_binding_cae': True})
    assert set(protected) == set(MFABypassVector)
    assert all(not item['vulnerable'] and not item['recommendations'] for item in protected.values())
    # An enabled SMS fallback remains vulnerable even when passkeys are available.
    assert evaluate({'mfa_type': 'sms', 'fido2_passkey': True})['sim_swap']['vulnerable']


def test_pillar_breakdown_consistency():
    config = environment(3)
    config['data'] = {}
    result = ZeroTrustEvaluator().evaluate_cisa_maturity(config)
    assert set(result.pillars) == set(ZTPillar)
    assert result.overall_score == pytest.approx(sum(p.score for p in result.pillars.values()) / 5)
    assert result.containment_factor == pytest.approx((4 * 0.70 + 0.1) / 5)
    for key, assessment in result.pillars.items():
        assert key == assessment.pillar
        assert 0 <= assessment.score <= 1
    assert result.pillars[ZTPillar.DATA].unmet_requirements


@pytest.mark.parametrize('stage', [1, 2, 3, 4])
def test_cumulative_stages(stage):
    result = ZeroTrustEvaluator().evaluate_cisa_maturity(environment(stage))
    assert all(p.level == stage for p in result.pillars.values())
    assert result.overall_score == pytest.approx((stage - 1) / 3)
    assert result.containment_factor == pytest.approx(CONTAINMENT[stage])


def test_higher_controls_do_not_skip_missing_prerequisite():
    config = environment(4)
    config['device']['mdm_managed'] = False
    assessment = ZeroTrustEvaluator().evaluate_cisa_maturity(config).pillars[ZTPillar.DEVICE]
    assert assessment.level == MaturityLevel.TRADITIONAL
    assert assessment.unmet_requirements == ('initial.mdm_managed',)


@pytest.mark.parametrize('config', [None, {'device': None}, {'device': {'mdm_managed': 'false'}},
                                  {'identity': {'mfa_type': 'typo'}}])
def test_invalid_environment(config):
    with pytest.raises(ValueError):
        ZeroTrustEvaluator().evaluate_cisa_maturity(config)


@pytest.mark.parametrize('config', [None, {'mfa_type': 'unknown'}, {'number_matching': 'false'},
                                  {'token_binding_cae': 1}])
def test_invalid_authentication(config):
    with pytest.raises(ValueError):
        ZeroTrustEvaluator().evaluate_mfa_resilience(config)


@pytest.mark.parametrize('score', [-0.1, 1.1, float('nan'), float('inf')])
def test_score_validation(score):
    dummy_pillars = {
        pillar: PillarAssessment(pillar, MaturityLevel.TRADITIONAL, 0.0, ())
        for pillar in ZTPillar
    }
    with pytest.raises(ValueError, match='finite and within'):
        PillarAssessment(ZTPillar.IDENTITY, MaturityLevel.INITIAL, score, [])
    with pytest.raises(ValueError, match='finite and within'):
        ZeroTrustAssessmentResult(score, dummy_pillars, 0.1)
    with pytest.raises(ValueError, match='finite and within'):
        ZeroTrustAssessmentResult(0.0, dummy_pillars, score)


@pytest.mark.parametrize('score', [0.0, 1.0])
def test_score_endpoints_are_valid(score):
    pillars = {p: PillarAssessment(p, MaturityLevel.TRADITIONAL, score, ()) for p in ZTPillar}
    result = ZeroTrustAssessmentResult(score, pillars, score)
    assert result.overall_score == result.containment_factor == score


def test_cisa_maturity_optimal_literal():
    config = {
        'identity': {'mfa_type': 'fido2', 'conditional_access': True,
                     'continuous_verification': True, 'just_in_time_access': True},
        'device': {'mdm_managed': True, 'edr_enabled': True, 'device_compliance_required': True,
                   'continuous_monitoring': True, 'automated_remediation': True},
        'network': {'segmentation': True, 'microsegmentation': True, 'encrypted_traffic': True,
                    'dynamic_policy': True, 'automated_response': True},
        'application': {'sso_enabled': True, 'least_privilege': True, 'workload_identity': True,
                        'continuous_authorization': True, 'automated_lifecycle': True},
        'data': {'inventory': True, 'classification': True, 'encryption_at_rest': True,
                 'dlp_enabled': True, 'dynamic_access': True, 'automated_classification': True},
    }
    result = ZeroTrustEvaluator().evaluate_cisa_maturity(config)
    assert result.overall_score == 1.0
    assert result.containment_factor == pytest.approx(0.95)
    assert all(p.level == MaturityLevel.OPTIMAL and not p.unmet_requirements
               for p in result.pillars.values())


@pytest.mark.parametrize(('config', 'message'), [
    ({'identiy': {}}, 'unknown pillar: identiy'),
    ({'identity': {'unknown_key': True}}, 'unknown configuration key: unknown_key'),
    ({'identity': {'number_matchng': True}}, 'unknown configuration key: number_matchng'),
    ({'device': {'mdm_manged': True}}, 'unknown configuration key: mdm_manged'),
    ({'network': {'microsegmetation': True}}, 'unknown configuration key: microsegmetation'),
    ({'application': {'sso_enabld': True}}, 'unknown configuration key: sso_enabld'),
    ({'data': {'inventry': True}}, 'unknown configuration key: inventry'),
])
def test_unknown_keys_raise_error(config, message):
    with pytest.raises(ValueError, match=message):
        ZeroTrustEvaluator().evaluate_cisa_maturity(config)


@pytest.mark.parametrize('key', ['number_matchng', 'cae', 'unknown_key'])
def test_unknown_authentication_keys_raise_error(key):
    with pytest.raises(ValueError, match=f'unknown authentication key: {key}'):
        ZeroTrustEvaluator().evaluate_mfa_resilience({key: True})


def test_sms_fallback_blocks_advanced_identity():
    config = environment(4)
    config['identity']['mfa_type'] = 'SMS'
    # A caller cannot override the derived requirement to bypass the check.
    config['identity']['sms_fallback_disabled'] = True
    result = ZeroTrustEvaluator().evaluate_cisa_maturity(config)
    identity = result.pillars[ZTPillar.IDENTITY]
    assert identity.level == MaturityLevel.INITIAL
    assert 'advanced.sms_fallback_disabled' in identity.unmet_requirements
    assert ZeroTrustEvaluator().evaluate_mfa_resilience(
        {'mfa_type': 'sms', 'fido2_passkey': True}
    )['sim_swap']['vulnerable']


def test_assessment_is_immutable_and_copies_inputs():
    unmet = ['initial.mdm_managed']
    assessment = PillarAssessment(ZTPillar.DEVICE, MaturityLevel.TRADITIONAL, 0.0, unmet)
    unmet.clear()
    assert assessment.unmet_requirements == ('initial.mdm_managed',)
    pillars = {p: PillarAssessment(p, MaturityLevel.TRADITIONAL, 0.0, ()) for p in ZTPillar}
    pillars[ZTPillar.DEVICE] = assessment
    result = ZeroTrustAssessmentResult(0.0, pillars, 0.1)
    pillars.clear()
    assert set(result.pillars) == set(ZTPillar)
    with pytest.raises(TypeError):
        result.pillars[ZTPillar.DEVICE] = assessment
    with pytest.raises(TypeError):
        assessment.unmet_requirements[0] = 'changed'
    with pytest.raises(FrozenInstanceError):
        assessment.score = 1.0
    with pytest.raises(FrozenInstanceError):
        result.pillars = {}


def test_result_requires_five_pillars():
    with pytest.raises(ValueError, match='five pillars'):
        ZeroTrustAssessmentResult(0, {}, 0.1)


def test_yaml_assets_and_profile_match_engine():
    profile = yaml.safe_load((ROOT / 'profiles/zerotrust_cisa_maturity.yaml').read_text(encoding='utf-8'))
    assert set(profile['pillars']) == set(ZTPillar)
    for pillar, stages in CHECKLISTS.items():
        criteria = profile['pillars'][pillar.value]
        assert criteria['traditional']['requirements'] == []
        for level, requirements in zip(('initial', 'advanced', 'optimal'), stages):
            assert criteria[level]['requirements'] == list(requirements)
    framework = yaml.safe_load((ROOT / 'frameworks/nist_sp800_207_zta.yaml').read_text(encoding='utf-8'))
    assert len({s['id'] for s in framework['input_sources']}) == 7
    assert set(framework['architecture']['control_plane']['pdp']) == {'policy_engine', 'policy_administrator'}
    rules = yaml.safe_load((ROOT / 'detections/identity_mfa_bypass_rules.yaml').read_text(encoding='utf-8'))
    assert len(rules['rules']) == 2
    assert all(rule['kql'] and rule['logsource'] for rule in rules['rules'])

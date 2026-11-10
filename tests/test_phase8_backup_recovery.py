"""Phase 8 policy contracts and deterministic recovery calculations."""

from copy import deepcopy
import json
from math import isinf
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from cybermatch.defense.backup_recovery_simulator import simulate_ransomware_recovery as simulate

ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / 'configs/backup_resilience/ransomware_backup_destruction.json').read_text(encoding="utf-8"))


@pytest.fixture
def policy():
    return deepcopy(CATALOG['hardened_32110_resilient'])


def test_legacy_destruction():
    result = simulate(CATALOG['legacy_vulnerable_backup'])
    assert not result['backup_survived']
    assert isinf(result['actual_rpo_hours']) and isinf(result['actual_rto_hours'])
    assert result['ransom_payment_forced'] and not result['recovery_successful']
    assert result['failure_reasons'] and result['recommendations']


def test_hardened_recovery_and_no_mutation(policy):
    original = deepcopy(policy)
    result = simulate(policy)
    assert policy == original
    assert result['backup_survived'] and result['compliant_32110']
    assert result['actual_rpo_hours'] == 4.0
    assert result['actual_rto_hours'] == 6.0
    assert result['recovery_successful'] and not result['ransom_payment_forced']
    assert not result['failure_reasons']


def test_unverified_penalty(policy):
    policy['rule_32110']['verified_zero_error_restore'] = False
    assert simulate(policy)['actual_rto_hours'] == 10.0


def test_missing_logs_penalty(policy):
    policy['protected_scopes']['audit_logs_and_iac_preserved'] = False
    assert simulate(policy)['actual_rto_hours'] == 174.0


def test_penalty_order(policy):
    policy['rule_32110']['verified_zero_error_restore'] = False
    policy['protected_scopes']['audit_logs_and_iac_preserved'] = False
    assert simulate(policy)['actual_rto_hours'] == 178.0


@pytest.mark.parametrize('dual', [False, True])
def test_governance_priority_even_with_isolation_and_airgap(policy, dual):
    policy['protection_controls'].update(worm_mode='governance', delete_requires_dual_auth=dual)
    assert simulate(policy)['backup_survived'] is dual


@pytest.mark.parametrize('control,value', [
    ('worm_mode', 'compliance'), ('air_gap_type', 'physical_lto'),
])
def test_independent_survival_controls(control, value):
    policy = deepcopy(CATALOG['legacy_vulnerable_backup'])
    policy['protection_controls'][control] = value
    assert simulate(policy)['backup_survived']


def test_no_domain_admin():
    assert simulate(CATALOG['legacy_vulnerable_backup'], False)['backup_survived']


def test_defaults_and_partial_operational(policy):
    del policy['operational']
    result = simulate(policy)
    assert result['actual_rpo_hours'] == 24.0 and result['actual_rto_hours'] == 6.0
    policy['operational'] = {'backup_frequency_hours': 2.0}
    assert simulate(policy)['actual_rpo_hours'] == 2.0


@pytest.mark.parametrize('field,value', [
    ('total_copies', 2), ('media_types', 1), ('offsite_copies', 0),
    ('immutable_airgap_copies', 0), ('verified_zero_error_restore', False),
])
def test_each_compliance_condition(policy, field, value):
    policy['rule_32110'][field] = value
    assert not simulate(policy)['compliant_32110']


@pytest.mark.parametrize('rpo,rto,forced', [(4, 6, False), (3, 6, False), (4, 5, False), (3, 5, True)])
def test_target_boundaries_and_payment_flag(policy, rpo, rto, forced):
    policy['targets'].update(target_rpo_hours=rpo, target_rto_hours=rto)
    result = simulate(policy)
    assert result['rpo_met'] is (rpo >= 4)
    assert result['rto_met'] is (rto >= 6)
    assert result['ransom_payment_forced'] is forced


def test_volume_throughput_and_scan(policy):
    policy['operational']['restore_throughput_tb_per_hour'] = 2.0
    policy['protection_controls']['malware_scan_on_restore'] = False
    assert simulate(policy, data_volume_tb=20.0)['actual_rto_hours'] == 34.0


@pytest.mark.parametrize('value', [None, [], 'policy', 1])
def test_invalid_policy_type(value):
    with pytest.raises(ValueError):
        simulate(value)


@pytest.mark.parametrize('value', [None, 1, 'true'])
def test_invalid_attacker_flag(policy, value):
    with pytest.raises(ValueError):
        simulate(policy, attacker_has_domain_admin=value)


@pytest.mark.parametrize('value', [None, True, '10', 0, -1, float('nan'), float('inf'), -float('inf')])
def test_invalid_volume(policy, value):
    with pytest.raises(ValueError):
        simulate(policy, data_volume_tb=value)


@pytest.mark.parametrize('section,field,value', [
    ('rule_32110', 'total_copies', True), ('rule_32110', 'total_copies', 1.5),
    ('rule_32110', 'total_copies', 0), ('rule_32110', 'offsite_copies', -1),
    ('rule_32110', 'verified_zero_error_restore', 1),
    ('protection_controls', 'worm_mode', 'invalid'),
    ('protection_controls', 'air_gap_type', 'invalid'),
    ('protection_controls', 'ad_domain_isolated', 'false'),
    ('targets', 'target_rpo_hours', -1), ('targets', 'target_rto_hours', 0),
    ('targets', 'target_rpo_hours', float('nan')),
    ('operational', 'backup_frequency_hours', float('inf')),
    ('operational', 'backup_frequency_hours', 0),
    ('operational', 'restore_throughput_tb_per_hour', 0),
    ('operational', 'restore_throughput_tb_per_hour', -1),
    ('operational', 'restore_throughput_tb_per_hour', True),
])
def test_invalid_nested_values(policy, section, field, value):
    policy[section][field] = value
    with pytest.raises(ValueError):
        simulate(policy)


@pytest.mark.parametrize('field', ['policy_id', 'organization_type', 'rule_32110',
                                  'protection_controls', 'protected_scopes', 'targets'])
def test_required_sections(policy, field):
    del policy[field]
    with pytest.raises(ValueError):
        simulate(policy)


def test_required_nested_field(policy):
    del policy['targets']['target_rpo_hours']
    with pytest.raises(ValueError):
        simulate(policy)


def test_invalid_organization(policy):
    policy['organization_type'] = 'unknown'
    with pytest.raises(ValueError):
        simulate(policy)


def test_computation_overflow(policy):
    policy['operational']['restore_throughput_tb_per_hour'] = 1e-300
    with pytest.raises(ValueError):
        simulate(policy, data_volume_tb=1e300)


def test_schema_and_catalog():
    schema = json.loads((ROOT / 'cybermatch/schemas/backup-resilience-policy.schema.json').read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    assert set(CATALOG) == {'legacy_vulnerable_backup', 'hardened_32110_resilient'}
    for name, policy in CATALOG.items():
        validator.validate(policy)
        assert policy['policy_id'] == name


@pytest.mark.parametrize('field', ['offsite_copies', 'immutable_airgap_copies', 'media_types'])
def test_copy_count_contradictions(policy, field):
    policy['rule_32110'][field] = 4
    with pytest.raises(ValueError, match='コピー数またはメディア種類の指定に論理的矛盾があります。'):
        simulate(policy)


def test_protection_control_contradiction(policy):
    policy['protection_controls'].update(worm_mode='none', air_gap_type='none')
    with pytest.raises(ValueError, match='保護コントロール'):
        simulate(policy)


@pytest.mark.parametrize('isolated', [False, True])
@pytest.mark.parametrize('worm', ['none', 'governance', 'compliance'])
@pytest.mark.parametrize('gap', ['none', 'logical', 'physical_lto'])
@pytest.mark.parametrize('dual', [False, True])
def test_survival_matrix(policy, isolated, worm, gap, dual):
    policy['rule_32110']['immutable_airgap_copies'] = 0
    policy['protection_controls'].update(ad_domain_isolated=isolated, worm_mode=worm,
                                         air_gap_type=gap, delete_requires_dual_auth=dual)
    expected = (worm == 'compliance' or gap == 'physical_lto'
                or (worm == 'governance' and dual) or (isolated and gap == 'logical'))
    if worm == 'governance' and not dual:
        expected = False
    assert simulate(policy)['backup_survived'] is expected


def test_vm_db_consistency_penalty(policy):
    baseline = simulate(policy)['actual_rto_hours']
    policy['protected_scopes']['vm_and_db_consistent'] = False
    result = simulate(policy)
    assert result['actual_rto_hours'] == baseline + 12.0
    assert 'DB静止点未確保による整合性修復作業に12時間を加算しました。' in result['failure_reasons']
    assert 'VSS等の静止点連携スナップショットを有効化してください。' in result['recommendations']


@pytest.mark.parametrize('organization,penalty', [('manufacturing_ot', 48.0), ('smb', 0.0)])
def test_ot_image_penalty(policy, organization, penalty):
    policy['organization_type'] = organization
    policy['protected_scopes']['ot_system_image_preserved'] = False
    result = simulate(policy)
    assert result['actual_rto_hours'] == 6.0 + penalty
    assert any('ゴールデンイメージ' in message for message in result['recommendations']) is bool(penalty)


def test_reinfection_penalty(policy):
    policy['protection_controls']['malware_scan_on_restore'] = False
    result = simulate(policy)
    assert result['actual_rto_hours'] == 2.0 + 24.0
    assert '復元時のマルウェアスキャン未実施により、再感染インシデント対応（+24時間）が発生しました。' in result['failure_reasons']
    assert '復元時のマルウェアスキャンを実施し、再感染を防止してください。' in result['recommendations']


def test_all_penalties_are_additive(policy):
    policy['organization_type'] = 'manufacturing_ot'
    policy['rule_32110']['verified_zero_error_restore'] = False
    policy['protected_scopes'] = dict.fromkeys(policy['protected_scopes'], False)
    policy['protection_controls']['malware_scan_on_restore'] = False
    assert simulate(policy)['actual_rto_hours'] == 2.0 * 3 + 168 + 12 + 48 + 24


@pytest.mark.parametrize('verified,throughput', [(True, '2.5'), (False, '7.5')])
def test_target_design_values(policy, verified, throughput):
    policy['rule_32110']['verified_zero_error_restore'] = verified
    messages = simulate(policy)['recommendations']
    assert '推奨バックアップ間隔は4時間以下です。' in messages
    assert any(f'{throughput} TB/h以上' in message for message in messages)


@pytest.mark.parametrize('target_rto', [4.0, 3.0])
def test_target_below_fixed_delay(policy, target_rto):
    policy['targets']['target_rto_hours'] = target_rto
    assert any('有限のリストアスループット' in message for message in simulate(policy)['recommendations'])


def test_zero_rpo_design(policy):
    policy['targets']['target_rpo_hours'] = 0
    assert any('継続的データ保護' in message for message in simulate(policy)['recommendations'])


def test_validation_error_includes_path(policy):
    policy['protection_controls']['worm_mode'] = 'invalid'
    with pytest.raises(ValueError, match='/protection_controls/worm_mode'):
        simulate(policy)

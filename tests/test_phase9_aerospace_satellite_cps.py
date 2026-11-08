"""Phase 9 aerospace CPS contracts, boundaries and regression coverage."""
from copy import deepcopy
from dataclasses import replace
import json
import math
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from cybermatch.defense.cps_safety_gate import (
    ADSBVerificationResult, AvionicsDomain, CPSAction, SatelliteTelemetryState,
    evaluate_cps_mission_resilience, verify_adsb_track,
    verify_avionics_domain_boundary, verify_navigation_integrity,
    verify_satellite_cfs_command, simulation_only_verifier,
)

ROOT = Path(__file__).resolve().parents[1]
SIG = 'CCSDS_SDLS_VALID_SIG'
STATE = SatelliteTelemetryState(0.8, 1.0, 20.0, False)


def command(**changes):
    args = dict(command_id='cfs_status', signature=SIG, sequence_number=2,
                last_received_seq=1, telemetry=STATE, signature_verifier=simulation_only_verifier)
    args.update(changes)
    return verify_satellite_cfs_command(**args)


@pytest.mark.parametrize('path,schema', [
    ('topologies/aerospace_avionics.json', 'topology'),
    ('topologies/satellite_space_ground.json', 'topology'),
    ('scenarios/catalog/aerospace_satellite_cps.json', 'scenario'),
])
def test_schema(path, schema):
    spec = json.loads((ROOT / f'cybermatch/schemas/{schema}.schema.json').read_text(encoding='utf-8'))
    data = json.loads((ROOT / path).read_text(encoding='utf-8'))
    Draft202012Validator.check_schema(spec)
    Draft202012Validator(spec).validate(data)
    if schema == 'topology':
        names = {z['name'] for z in data['zones']}
        assert len(names) == len(data['zones'])
        assert [z['node_id'] for z in data['zones']] == list(range(len(names)))
        assert all(e['source'] in names and e['target'] in names and not e['bidirectional'] for e in data['edges'])
    else:
        assert all((ROOT / p).is_file() for p in data['products'])


@pytest.mark.parametrize('signature', [None, '', 'invalid', '無効な署名'])
def test_signature(signature):
    result = command(signature=signature, sequence_number=1)
    assert result.action == CPSAction.REJECT
    assert result.rejection_reason == ('missing_signature_or_verifier_fail_closed'
                                       if signature is None else 'missing_or_invalid_ccsds_signature')
    assert not result.safe_hold_mode and not result.is_allowed


@pytest.mark.parametrize('signature', [SIG, None, 'invalid'])
def test_unknown_command_rejected(signature):
    def unexpected_verifier(command_id, sequence_number, supplied_signature):
        pytest.fail('Unknown commands must not reach signature verification')

    result = command(command_id='cfs_unknown_exploit', signature=signature,
                     signature_verifier=unexpected_verifier)
    assert result.action == CPSAction.REJECT
    assert result.rejection_reason == 'unknown_command_id'
    assert not result.safe_hold_mode and not result.is_allowed


@pytest.mark.parametrize('cmd,state', [
    ('cfs_eps_battery_heater_max', replace(STATE, battery_soc=0.29)),
    ('cfs_adcs_thruster_fire', replace(STATE, angular_velocity_deg_s=5.01)),
    ('cfs_comm_transponder_shutdown', replace(STATE, transponder_critical=True)),
])
@pytest.mark.parametrize('signature', [None, '', 'invalid'])
def test_invalid_signature_cannot_trigger_safe_hold(cmd, state, signature):
    result = command(command_id=cmd, telemetry=state, signature=signature)
    assert result.action == CPSAction.REJECT
    assert result.rejection_reason == ('missing_signature_or_verifier_fail_closed'
                                       if signature is None else 'missing_or_invalid_ccsds_signature')
    assert not result.safe_hold_mode and not result.is_allowed


@pytest.mark.parametrize('signature,valid', [('custom_signature', True), (SIG, False)])
def test_injected_signature_verifier(signature, valid):
    calls = []

    def verifier(command_id, sequence_number, supplied_signature):
        calls.append((command_id, sequence_number, supplied_signature))
        return supplied_signature == 'custom_signature'

    result = command(signature=signature, signature_verifier=verifier)
    assert calls == [('cfs_status', 2, signature)]
    assert result.action == (CPSAction.ALLOW if valid else CPSAction.REJECT)
    assert result.is_allowed is valid
    assert not result.safe_hold_mode
    assert result.rejection_reason == (None if valid else 'missing_or_invalid_ccsds_signature')


def test_missing_signature_does_not_call_injected_verifier():
    def verifier(command_id, sequence_number, signature):
        pytest.fail('Missing signatures must not reach the verifier')

    result = command(signature=None, signature_verifier=verifier)
    assert result.action == CPSAction.REJECT
    assert result.rejection_reason == 'missing_signature_or_verifier_fail_closed'
    assert not result.safe_hold_mode and not result.is_allowed


@pytest.mark.parametrize('seq', [0, 1])
def test_replay(seq):
    result = command(sequence_number=seq)
    assert result.action == CPSAction.REJECT
    assert result.rejection_reason == 'replay_attack_detected'
    assert not result.safe_hold_mode and not result.is_allowed


@pytest.mark.parametrize('cmd,state,reason', [
    ('cfs_eps_battery_heater_max', replace(STATE, battery_soc=0.29), 'battery_depletion_hazard'),
    ('cfs_adcs_thruster_fire', replace(STATE, angular_velocity_deg_s=5.01), 'attitude_instability_hazard'),
    ('cfs_adcs_thruster_fire', replace(STATE, angular_velocity_deg_s=-6.0), 'attitude_instability_hazard'),
    ('cfs_comm_transponder_shutdown', replace(STATE, transponder_critical=True), 'unrecoverable_comm_loss_hazard'),
])
def test_hazards(cmd, state, reason):
    result = command(command_id=cmd, telemetry=state)
    assert result.action == CPSAction.REJECT_AND_SAFE_HOLD
    assert result.safe_hold_mode and not result.is_allowed
    assert result.rejection_reason == reason


@pytest.mark.parametrize('cmd,state', [
    ('cfs_status', STATE),
    ('cfs_payload_camera_take', STATE),
    ('cfs_eps_battery_heater_max', replace(STATE, battery_soc=0.30)),
    ('cfs_adcs_thruster_fire', replace(STATE, angular_velocity_deg_s=5.0)),
    ('cfs_comm_transponder_shutdown', STATE),
])
def test_safe_commands(cmd, state):
    result = command(command_id=cmd, telemetry=state)
    assert result.action == CPSAction.ALLOW and result.is_allowed
    assert not result.safe_hold_mode and result.rejection_reason is None


@pytest.mark.parametrize('delta,cn0,jam,spoof', [
    (0, 40, False, False), (2, 25, False, False), (2, 55, False, False),
    (2.001, 40, False, True), (0, 55.001, False, True),
    (0, 24.999, True, False), (3, 20, True, True),
])
def test_navigation(delta, cn0, jam, spoof):
    result = verify_navigation_integrity((delta, 0, 0), (0, 0, 0), cn0)
    assert result.position_divergence_km == delta
    assert result.gnss_jamming_detected is jam
    assert result.gnss_spoofing_detected is spoof
    assert result.action == (CPSAction.INS_FALLBACK if jam or spoof else CPSAction.ALLOW)
    assert result.nav_mode == ('INS_FALLBACK' if jam or spoof else 'GNSS_INS_COUPLED')
    assert result.alert == ('gnss_jamming_snr_drop' if jam else 'gnss_spoofing_position_divergence' if spoof else None)


def test_three_dimensional_distance():
    assert verify_navigation_integrity((1, 2, 2), (0, 0, 0), 40).position_divergence_km == 3


@pytest.mark.parametrize('mlat,radar,ghost', [(None, False, True), ((6, 0), False, True), ((3, 4), False, False), (None, True, False), ((100, 0), True, True), ((3, 4), True, False), ((5.001, 0), True, True)])
def test_adsb(mlat, radar, ghost):
    result = verify_adsb_track('ABC123', (0, 0), mlat, radar)
    assert isinstance(result, ADSBVerificationResult)
    assert result.is_ghost_aircraft is ghost
    assert result.action == (CPSAction.DROP_GHOST_TARGET if ghost else CPSAction.ALLOW)
    assert result.track_status == ('ghost_dropped' if ghost else 'track_confirmed')
    assert result.alert == ('radar_mlat_discrepancy_detected' if ghost and radar else 'unverified_adsb_ghost_track' if ghost else None)


@pytest.mark.parametrize('source,target,traffic,action,reason', [
    ('PIESD', 'PIESD', 'read', CPSAction.ALLOW, None),
    ('PIESD', 'PIESD', 'write', CPSAction.ALLOW, None),
    ('PIESD', 'AISD', 'read', CPSAction.ALLOW, None),
    ('PIESD', 'AISD', 'write', CPSAction.DENY_BOUNDARY_VIOLATION, 'unauthorized_write_from_piesd_to_aisd'),
    ('PIESD', 'ACD', 'read', CPSAction.DENY_BOUNDARY_VIOLATION, 'unspecified_cross_domain_flow'),
    ('PIESD', 'ACD', 'write', CPSAction.DENY_BOUNDARY_VIOLATION, 'data_diode_violation_inbound_write_to_acd_prohibited'),
    ('AISD', 'PIESD', 'read', CPSAction.DENY_BOUNDARY_VIOLATION, 'unspecified_cross_domain_flow'),
    ('AISD', 'PIESD', 'write', CPSAction.DENY_BOUNDARY_VIOLATION, 'unspecified_cross_domain_flow'),
    ('AISD', 'AISD', 'read', CPSAction.ALLOW, None),
    ('AISD', 'AISD', 'write', CPSAction.ALLOW, None),
    ('AISD', 'ACD', 'read', CPSAction.DENY_BOUNDARY_VIOLATION, 'unspecified_cross_domain_flow'),
    ('AISD', 'ACD', 'write', CPSAction.DENY_BOUNDARY_VIOLATION, 'data_diode_violation_inbound_write_to_acd_prohibited'),
    ('ACD', 'PIESD', 'read', CPSAction.DENY_BOUNDARY_VIOLATION, 'prohibited_direct_flow_from_acd_to_piesd'),
    ('ACD', 'PIESD', 'write', CPSAction.DENY_BOUNDARY_VIOLATION, 'prohibited_direct_flow_from_acd_to_piesd'),
    ('ACD', 'AISD', 'read', CPSAction.ALLOW, None),
    ('ACD', 'AISD', 'write', CPSAction.ALLOW, None),
    ('ACD', 'ACD', 'read', CPSAction.ALLOW, None),
    ('ACD', 'ACD', 'write', CPSAction.ALLOW, None),
])
def test_domain_matrix(source, target, traffic, action, reason):
    result = verify_avionics_domain_boundary(source, target, traffic)
    assert result.action == action
    assert result.is_allowed is (action == CPSAction.ALLOW)
    assert result.violation_reason == reason


@pytest.mark.parametrize('radar_coords,radar_contact,mlat,alert', [
    ((3, 4), True, None, None),
    ((5.001, 0), True, None, 'radar_adsb_discrepancy_detected'),
    ((100, 0), True, (0, 0), 'radar_adsb_discrepancy_detected'),
    ((100, 0), False, (0, 0), 'radar_adsb_discrepancy_detected'),
    ((0, 0), True, (100, 0), 'radar_mlat_discrepancy_detected'),
])
def test_adsb_radar_position(radar_coords, radar_contact, mlat, alert):
    result = verify_adsb_track('ABC', (0, 0), mlat, radar_contact,
                               radar_coords=radar_coords)
    assert result.alert == alert
    assert result.is_ghost_aircraft is (alert is not None)
    assert result.action == (CPSAction.ALLOW if alert is None else CPSAction.DROP_GHOST_TARGET)
    assert result.track_status == ('track_confirmed' if alert is None else 'ghost_dropped')
    summary = evaluate_cps_mission_resilience([], [], [], [result])
    assert summary['policy_handling_rate'] == summary['cps_resilience_score'] == 1.0


@pytest.mark.parametrize('field,value', [
    ('command_id', ''), ('command_id', '  '), ('command_id', None),
    ('signature', 1), ('sequence_number', -1), ('sequence_number', True),
    ('sequence_number', 1.5), ('last_received_seq', None),
    ('last_received_seq', -2), ('telemetry', {}),
])
def test_invalid_command(field, value):
    with pytest.raises(ValueError):
        command(**{field: value})


@pytest.mark.parametrize('field', ['battery_soc', 'angular_velocity_deg_s', 'sun_pointing_angle_deg'])
@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf'), None, True, '1'])
def test_invalid_telemetry(field, value):
    with pytest.raises(ValueError):
        command(telemetry=replace(STATE, **{field: value}))


@pytest.mark.parametrize('state', [replace(STATE, battery_soc=-0.1), replace(STATE, battery_soc=1.1), replace(STATE, transponder_critical=1)])
def test_telemetry_ranges(state):
    with pytest.raises(ValueError):
        command(telemetry=state)


@pytest.mark.parametrize('coords', [None, (), (0, 0), [0, 0, 0], (0, True, 0)])
def test_invalid_navigation_coords(coords):
    for first, second in [(coords, (0, 0, 0)), ((0, 0, 0), coords)]:
        with pytest.raises(ValueError):
            verify_navigation_integrity(first, second, 40)


@pytest.mark.parametrize('cn0', [None, True, '40'])
def test_invalid_cn0(cn0):
    with pytest.raises(ValueError):
        verify_navigation_integrity((0, 0, 0), (0, 0, 0), cn0)


@pytest.mark.parametrize('args', [('', (0, 0), None, False), (1, (0, 0), None, False), ('ABC', (0, 0), (0,), False), ('ABC', (0, 0), None, 1)])
def test_invalid_adsb(args):
    with pytest.raises(ValueError):
        verify_adsb_track(*args)


@pytest.mark.parametrize('args', [('', 'ACD', 'write'), ('AISD', None, 'read'), ([], 'ACD', 'read'), ('ACD', 'AISD', 'execute'), ('ACD', 'AISD', [])])
def test_invalid_domains(args):
    with pytest.raises(ValueError):
        verify_avionics_domain_boundary(*args)


def test_distance_overflow():
    result = verify_navigation_integrity((1e308, 0, 0), (-1e308, 0, 0), 40)
    assert result.alert == 'sensor_anomaly_invalid_coordinates_ins_fallback'
    assert result.action == CPSAction.INS_FALLBACK
    assert verify_adsb_track('ABC', (1e308, 0), (-1e308, 0), True).alert == 'malformed_adsb_coordinates_ghost_dropped'
    assert verify_adsb_track('ABC', (1e308, 0), None, True, (-1e308, 0)).alert == 'malformed_adsb_coordinates_ghost_dropped'


def test_no_mutation_and_summary():
    inputs = dict(command_id='cfs_status', signature=SIG, sequence_number=2, last_received_seq=1, telemetry=STATE, signature_verifier=simulation_only_verifier)
    original = deepcopy(inputs)
    satellite = [verify_satellite_cfs_command(**inputs), command(signature=None)]
    nav_args = ((0, 0, 3), (0, 0, 0), 40)
    nav = [verify_navigation_integrity(*nav_args)]
    domain_args = ('PIESD', 'ACD', 'write')
    domains = [verify_avionics_domain_boundary(*domain_args)]
    adsb_args = ('ABC123', (0, 0), (3, 4), False)
    before = deepcopy((nav_args, domain_args, adsb_args))
    verify_adsb_track(*adsb_args)
    lists = deepcopy((satellite, nav, domains))
    result = evaluate_cps_mission_resilience(satellite, nav, domains)
    assert inputs == original and lists == (satellite, nav, domains)
    assert before == (nav_args, domain_args, adsb_args)
    assert type(result['cps_resilience_score']) is float
    assert math.isfinite(result['cps_resilience_score']) and 0 <= result['cps_resilience_score'] <= 1
    assert result['policy_handling_rate'] == result['cps_resilience_score'] == 1.0
    assert result['incidents_prevented'] == 3
    assert result['subsystems']['satellite']['defense_success_count'] == 2
    assert result['summary_markdown'].startswith('# CPS')
    empty = evaluate_cps_mission_resilience([], [], [])
    assert empty['policy_handling_rate'] == empty['cps_resilience_score'] == 0.0


@pytest.mark.parametrize('args', [(None, [], []), ([{}], [], []), ([], [command()], []), ([], [], ['bad'])])
def test_invalid_summary(args):
    with pytest.raises(ValueError):
        evaluate_cps_mission_resilience(*args)


@pytest.mark.parametrize('subsystem', [0, 1, 2])
@pytest.mark.parametrize('invalid', [None, {}, (), [None], [{}]])
def test_invalid_summary_result_types(subsystem, invalid):
    args = [[], [], []]
    args[subsystem] = invalid
    with pytest.raises(ValueError):
        evaluate_cps_mission_resilience(*args)


@pytest.mark.parametrize('subsystem,valid_result,incompatible_action', [
    (0, command(), CPSAction.INS_FALLBACK),
    (1, verify_navigation_integrity((0, 0, 0), (0, 0, 0), 40), CPSAction.REJECT),
    (2, verify_avionics_domain_boundary('ACD', 'ACD', 'read'), CPSAction.REJECT_AND_SAFE_HOLD),
])
@pytest.mark.parametrize('action_kind', ['incompatible', 'string', 'unknown', 'none', 'unhashable'])
def test_invalid_summary_actions(subsystem, valid_result, incompatible_action, action_kind):
    action = {
        'incompatible': incompatible_action,
        'string': 'allow',
        'unknown': 'invalid_action',
        'none': None,
        'unhashable': [],
    }[action_kind]
    args = [[], [], []]
    args[subsystem] = [replace(valid_result, action=action)]
    with pytest.raises(ValueError, match='invalid .* action'):
        evaluate_cps_mission_resilience(*args)


@pytest.mark.parametrize('value', [1, 'true', [], object(), None, False])
def test_verifier_requires_literal_true(value):
    assert command(signature_verifier=lambda *args: value).action == CPSAction.REJECT


def test_verifier_exception_fails_closed():
    def verifier(*args):
        raise RuntimeError('verification unavailable')
    assert command(signature_verifier=verifier).action == CPSAction.REJECT


def test_signature_binds_sequence():
    verifier = lambda cmd, seq, sig: (cmd, seq, sig) == ('cfs_status', 2, 'bound')
    assert command(signature='bound', signature_verifier=verifier).is_allowed
    assert command(signature='bound', sequence_number=3, signature_verifier=verifier).action == CPSAction.REJECT


@pytest.mark.parametrize('index,result', [
    (0, replace(command(), is_allowed=False)),
    (0, replace(command(), safe_hold_mode=True)),
    (0, replace(command(), rejection_reason='hazard')),
    (1, replace(verify_navigation_integrity((0, 0, 0), (0, 0, 0), 40), nav_mode='INS_FALLBACK')),
    (1, replace(verify_navigation_integrity((0, 0, 0), (0, 0, 0), 40), gnss_spoofing_detected=True)),
    (2, replace(verify_avionics_domain_boundary('ACD', 'AISD', 'read'), is_allowed=False)),
    (3, replace(verify_adsb_track('ABC', (0, 0), None, False), is_ghost_aircraft=False)),
    (3, replace(verify_adsb_track('ABC', (0, 0), None, True), alert='unexpected')),
])
def test_inconsistent_summary(index, result):
    args = [[], [], [], []]
    args[index] = [result]
    with pytest.raises(ValueError):
        evaluate_cps_mission_resilience(*args)


def test_integrated_summary_with_failed_policy_outcome():
    rejected = replace(command(signature=None), rejection_reason='unsupported_policy')
    adsb = [verify_adsb_track('ABC', (0, 0), (100, 0), True),
            verify_adsb_track('DEF', (0, 0), (0, 0), True)]
    before = deepcopy(adsb)
    result = evaluate_cps_mission_resilience([command(), rejected], [], [], adsb)
    assert result['policy_handling_rate'] == result['cps_resilience_score'] == 0.75
    assert result['incidents_prevented'] == 1
    assert result['subsystems']['adsb']['defense_success_count'] == 2
    assert adsb == before


@pytest.mark.parametrize('invalid', [(), {}, [None], [command()]])
def test_invalid_adsb_summary(invalid):
    with pytest.raises(ValueError):
        evaluate_cps_mission_resilience([], [], [], invalid)


def test_scenario_topology_safety_pipeline():
    scenario = json.loads((ROOT / 'scenarios/catalog/aerospace_satellite_cps.json').read_text(encoding='utf-8'))
    assert scenario['topology'] == {'preset': 'aerospace_avionics', 'path': 'topologies/aerospace_avionics.json'}
    topology = json.loads((ROOT / scenario['topology']['path']).read_text(encoding='utf-8'))
    assert topology['topology_id'] == scenario['topology']['preset']
    controls = {c['control_id'] for c in topology['controls']}
    assert {'data_diode_acd_isolation', 'adsb_mlat_cross_validator', 'gnss_ins_coupling_gate'} <= controls
    domains, nav, adsb = [], [], []
    for edge in topology['edges']:
        source = edge['source'].split('_', 1)[0]
        target = edge['target'].split('_', 1)[0]
        if source in AvionicsDomain._value2member_map_:
            domains.append(verify_avionics_domain_boundary(source, target, 'read'))
            domains.append(verify_avionics_domain_boundary(target, source, 'write'))
        elif source == 'GNSS':
            nav.append(verify_navigation_integrity((100, 0, 0), (0, 0, 0), 40))
        elif source == 'ADSB':
            adsb.append(verify_adsb_track('ABC123', (100, 0), (0, 0), True))
        else:
            pytest.fail(f'Unmapped topology source: {source}')
    satellite_topology = json.loads((ROOT / 'topologies/satellite_space_ground.json').read_text(encoding='utf-8'))
    assert any(e['target'] == 'ADCS_Attitude_Control' for e in satellite_topology['edges'])
    satellite = [command(command_id='cfs_adcs_thruster_fire', telemetry=replace(STATE, angular_velocity_deg_s=-6))]
    assert len(domains) == 4 and sum(r.is_allowed for r in domains) == 2
    assert len(nav) == len(adsb) == 1
    assert nav[0].action == CPSAction.INS_FALLBACK
    assert adsb[0].action == CPSAction.DROP_GHOST_TARGET
    assert satellite[0].action == CPSAction.REJECT_AND_SAFE_HOLD
    summary = evaluate_cps_mission_resilience(satellite, nav, domains, adsb)
    assert summary['cps_resilience_score'] == 1.0
    assert summary['incidents_prevented'] == 5
    assert sum(s['total_decisions'] for s in summary['subsystems'].values()) == 7


@pytest.mark.parametrize('explicit', [False, True])
def test_no_verifier_fails_closed(explicit):
    args = dict(command_id='cfs_status', signature=SIG, sequence_number=2,
                last_received_seq=1, telemetry=STATE)
    if explicit:
        args['signature_verifier'] = None
    result = verify_satellite_cfs_command(**args)
    assert result.action == CPSAction.REJECT
    assert result.rejection_reason == 'missing_signature_or_verifier_fail_closed'
    assert not result.is_allowed and not result.safe_hold_mode


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf'), 10**1000])
@pytest.mark.parametrize('field', ['gnss', 'ins', 'cn0'])
def test_navigation_sensor_anomaly(value, field):
    gnss = (value, 0, 0) if field == 'gnss' else (0, 0, 0)
    ins = (value, 0, 0) if field == 'ins' else (0, 0, 0)
    result = verify_navigation_integrity(gnss, ins, value if field == 'cn0' else 40)
    assert result.action == CPSAction.INS_FALLBACK
    assert result.gnss_spoofing_detected and not result.gnss_jamming_detected
    assert result.nav_mode == 'INS_FALLBACK'
    assert result.position_divergence_km == float('inf')
    assert result.alert == 'sensor_anomaly_invalid_coordinates_ins_fallback'
    assert evaluate_cps_mission_resilience([], [result], [])['cps_resilience_score'] == 1.0
    with pytest.raises(ValueError):
        evaluate_cps_mission_resilience([], [replace(result, gnss_jamming_detected=True)], [])


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf'), 10**1000])
@pytest.mark.parametrize('field', ['adsb', 'mlat', 'radar'])
def test_adsb_sensor_anomaly(value, field):
    adsb = (value, 0) if field == 'adsb' else (0, 0)
    mlat = (value, 0) if field == 'mlat' else (0, 0)
    radar = (value, 0) if field == 'radar' else None
    result = verify_adsb_track('ABC', adsb, mlat, True, radar)
    assert result.action == CPSAction.DROP_GHOST_TARGET
    assert result.is_ghost_aircraft and result.track_status == 'ghost_dropped'
    assert result.alert == 'malformed_adsb_coordinates_ghost_dropped'
    assert evaluate_cps_mission_resilience([], [], [], [result])['cps_resilience_score'] == 1.0


@pytest.mark.parametrize('coords', [None, (), [0, 0], (None, 0), ('0', 0), (True, 0)])
def test_adsb_programming_errors(coords):
    with pytest.raises(ValueError):
        verify_adsb_track('ABC', coords, None, True)
    if coords is not None:  # None explicitly means MLAT is unavailable.
        with pytest.raises(ValueError):
            verify_adsb_track('ABC', (0, 0), coords, True)
        with pytest.raises(ValueError):
            verify_adsb_track('ABC', (0, 0), None, True, coords)

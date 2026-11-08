"""Deterministic CPS policy simulation; the signature token is not cryptography.

Coordinates are Cartesian kilometres. These model thresholds are not certified
flight limits. Unspecified cross-domain flows fail closed.
"""

from dataclasses import dataclass
from enum import StrEnum
import hmac
import math
from typing import Callable


class AvionicsDomain(StrEnum):
    PIESD = "PIESD"
    AISD = "AISD"
    ACD = "ACD"


class CPSAction(StrEnum):
    ALLOW = "allow"
    REJECT = "reject"
    REJECT_AND_SAFE_HOLD = "reject_and_safe_hold"
    INS_FALLBACK = "ins_fallback"
    DROP_GHOST_TARGET = "drop_ghost_target"
    DENY_BOUNDARY_VIOLATION = "deny_boundary_violation"


MAX_SAFE_ANGULAR_VELOCITY_DEG_S = 5.0
MIN_SAFE_BATTERY_SOC = 0.30
GNSS_SPOOFING_MAX_DELTA_KM = 2.0
GNSS_JAMMING_MIN_CN0_DB_HZ = 25.0
GNSS_SPOOFING_MAX_CN0_DB_HZ = 55.0
ADSB_MAX_RADAR_DISCREPANCY_KM = 5.0
ALLOWED_CFS_COMMANDS: frozenset[str] = frozenset({
    "cfs_status",
    "cfs_eps_battery_heater_max",
    "cfs_adcs_thruster_fire",
    "cfs_comm_transponder_shutdown",
    "cfs_payload_camera_take",
})


@dataclass(frozen=True)
class SatelliteTelemetryState:
    battery_soc: float
    angular_velocity_deg_s: float
    sun_pointing_angle_deg: float
    transponder_critical: bool


@dataclass(frozen=True)
class CommandVerificationResult:
    action: CPSAction
    safe_hold_mode: bool
    rejection_reason: str | None
    is_allowed: bool


@dataclass(frozen=True)
class NavigationVerificationResult:
    action: CPSAction
    gnss_jamming_detected: bool
    gnss_spoofing_detected: bool
    nav_mode: str
    position_divergence_km: float
    alert: str | None


@dataclass(frozen=True)
class ADSBVerificationResult:
    action: CPSAction
    is_ghost_aircraft: bool
    track_status: str
    alert: str | None


@dataclass(frozen=True)
class DomainBoundaryResult:
    action: CPSAction
    is_allowed: bool
    violation_reason: str | None


def _number(value, name):
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be a finite number")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError(f"{name} must be a finite number")


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")


def _numeric_type(value, name):
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be numeric")


def _coords_finite(value, size) -> bool:
    """Reject programming errors; report nonfinite sensor numbers as anomalies."""
    if not isinstance(value, tuple) or len(value) != size:
        raise ValueError(f"coordinates must be a {size}-tuple in kilometres")
    for item in value:
        _numeric_type(item, "coordinate")
    return all(_finite(item) for item in value)


def _finite(value):
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _distance(left, right):
    try:
        return math.dist(left, right)
    except OverflowError:
        return float("inf")


def simulation_only_verifier(command_id: str, sequence_number: int, signature: str) -> bool:
    """Explicit simulation stub using constant-time comparison.

    The fixed token does not authenticate command ID or sequence. Production
    callers must inject a cryptographic verifier that binds both values.
    """
    return hmac.compare_digest(signature.encode("utf-8"), b"CCSDS_SDLS_VALID_SIG")


def verify_satellite_cfs_command(
    command_id: str, signature: str | None, sequence_number: int,
    last_received_seq: int, telemetry: SatelliteTelemetryState,
    signature_verifier: Callable[[str, int, str], bool] | None = None,
) -> CommandVerificationResult:
    """Verify command policy with an injectable signature verifier.

    Missing signatures or verifiers fail closed. Simulations must explicitly
    inject simulation_only_verifier; production requires cryptographic verification.
    """
    _text(command_id, "command_id")
    if signature is not None and not isinstance(signature, str):
        raise ValueError("signature must be a string or None")
    if type(sequence_number) is not int or sequence_number < 0:
        raise ValueError("sequence_number must be a nonnegative integer")
    if type(last_received_seq) is not int or last_received_seq < -1:
        raise ValueError("last_received_seq must be an integer >= -1")
    if not isinstance(telemetry, SatelliteTelemetryState):
        raise ValueError("telemetry must be SatelliteTelemetryState")
    for field in ("battery_soc", "angular_velocity_deg_s", "sun_pointing_angle_deg"):
        _number(getattr(telemetry, field), field)
    if not 0 <= telemetry.battery_soc <= 1:
        raise ValueError("battery_soc must be between zero and one")
    if type(telemetry.transponder_critical) is not bool:
        raise ValueError("transponder_critical must be boolean")
    if command_id not in ALLOWED_CFS_COMMANDS:
        return CommandVerificationResult(CPSAction.REJECT, False, "unknown_command_id", False)
    if signature is None or signature_verifier is None:
        return CommandVerificationResult(
            CPSAction.REJECT, False, "missing_signature_or_verifier_fail_closed", False
        )
    try:
        is_valid_sig = signature_verifier(command_id, sequence_number, signature) is True
    except Exception:
        is_valid_sig = False
    if not is_valid_sig:
        return CommandVerificationResult(CPSAction.REJECT, False, "missing_or_invalid_ccsds_signature", False)
    if sequence_number <= last_received_seq:
        return CommandVerificationResult(CPSAction.REJECT, False, "replay_attack_detected", False)
    reason = None
    if command_id == "cfs_eps_battery_heater_max" and telemetry.battery_soc < MIN_SAFE_BATTERY_SOC:
        reason = "battery_depletion_hazard"
    elif command_id == "cfs_adcs_thruster_fire" and abs(telemetry.angular_velocity_deg_s) > MAX_SAFE_ANGULAR_VELOCITY_DEG_S:
        reason = "attitude_instability_hazard"
    elif command_id == "cfs_comm_transponder_shutdown" and telemetry.transponder_critical:
        reason = "unrecoverable_comm_loss_hazard"
    if reason:
        return CommandVerificationResult(CPSAction.REJECT_AND_SAFE_HOLD, True, reason, False)
    return CommandVerificationResult(CPSAction.ALLOW, False, None, True)


def verify_navigation_integrity(
    gnss_coords: tuple[float, float, float],
    ins_coords: tuple[float, float, float], cn0_db_hz: float,
) -> NavigationVerificationResult:
    """Fall back on invalid sensor numbers, including distance overflow.

    Invalid tuple shapes or nonnumeric types remain programming errors.
    """
    gnss_finite = _coords_finite(gnss_coords, 3)
    ins_finite = _coords_finite(ins_coords, 3)
    _numeric_type(cn0_db_hz, "cn0_db_hz")
    delta = _distance(gnss_coords, ins_coords) if gnss_finite and ins_finite else float("inf")
    if not (gnss_finite and ins_finite and _finite(cn0_db_hz) and _finite(delta)):
        return NavigationVerificationResult(
            CPSAction.INS_FALLBACK, False, True, "INS_FALLBACK", float("inf"),
            "sensor_anomaly_invalid_coordinates_ins_fallback",
        )
    jamming = cn0_db_hz < GNSS_JAMMING_MIN_CN0_DB_HZ
    spoofing = delta > GNSS_SPOOFING_MAX_DELTA_KM or cn0_db_hz > GNSS_SPOOFING_MAX_CN0_DB_HZ
    alert = ("gnss_jamming_snr_drop" if jamming else
             "gnss_spoofing_position_divergence" if spoofing else None)
    return NavigationVerificationResult(
        CPSAction.INS_FALLBACK if alert else CPSAction.ALLOW, jamming, spoofing,
        "INS_FALLBACK" if alert else "GNSS_INS_COUPLED", delta, alert,
    )


def verify_adsb_track(
    target_icao: str, adsb_coords: tuple[float, float],
    mlat_coords: tuple[float, float] | None, radar_contact: bool,
    radar_coords: tuple[float, float] | None = None,
) -> ADSBVerificationResult:
    """Cross-check ADS-B against available MLAT and radar positions in kilometres."""
    _text(target_icao, "target_icao")
    adsb_finite = _coords_finite(adsb_coords, 2)
    mlat_finite = True if mlat_coords is None else _coords_finite(mlat_coords, 2)
    radar_finite = True if radar_coords is None else _coords_finite(radar_coords, 2)
    if type(radar_contact) is not bool:
        raise ValueError("radar_contact must be boolean")
    delta = None
    if adsb_finite and mlat_finite and mlat_coords is not None:
        delta = _distance(adsb_coords, mlat_coords)
    radar_delta = None
    if adsb_finite and radar_finite and radar_coords is not None:
        radar_delta = _distance(adsb_coords, radar_coords)
    if (not (adsb_finite and mlat_finite and radar_finite) or
            (delta is not None and not _finite(delta)) or
            (radar_delta is not None and not _finite(radar_delta))):
        return ADSBVerificationResult(
            CPSAction.DROP_GHOST_TARGET, True, "ghost_dropped",
            "malformed_adsb_coordinates_ghost_dropped",
        )
    if radar_delta is not None and radar_delta > ADSB_MAX_RADAR_DISCREPANCY_KM:
        return ADSBVerificationResult(
            CPSAction.DROP_GHOST_TARGET, True, "ghost_dropped",
            "radar_adsb_discrepancy_detected",
        )
    discrepancy = delta is not None and delta > ADSB_MAX_RADAR_DISCREPANCY_KM
    ghost = discrepancy or (not radar_contact and delta is None)
    return ADSBVerificationResult(
        CPSAction.DROP_GHOST_TARGET if ghost else CPSAction.ALLOW, ghost,
        "ghost_dropped" if ghost else "track_confirmed",
        "radar_mlat_discrepancy_detected" if radar_contact and discrepancy else
        "unverified_adsb_ghost_track" if ghost else None,
    )


def verify_avionics_domain_boundary(
    source_domain: str, target_domain: str, traffic_type: str,
) -> DomainBoundaryResult:
    """Treat both operations as data/messages sent from source to target.

    ACD -> AISD is outbound diode telemetry for both read and write. External
    writes into ACD are forbidden. PIESD -> AISD allows flight-map reads only;
    ACD -> PIESD direct communication is prohibited. Same-domain operations are
    allowed, and unspecified cross-domain flows fail closed.
    """
    for domain in (source_domain, target_domain):
        if not isinstance(domain, str):
            raise ValueError("unknown avionics domain")
        try:
            AvionicsDomain(domain)
        except ValueError as exc:
            raise ValueError("unknown avionics domain") from exc
    if not isinstance(traffic_type, str) or traffic_type not in ("read", "write"):
        raise ValueError("traffic_type must be read or write")
    reason = "unspecified_cross_domain_flow"
    if source_domain == "ACD" and target_domain == "PIESD":
        reason = "prohibited_direct_flow_from_acd_to_piesd"
    elif target_domain == "ACD" and source_domain != "ACD" and traffic_type == "write":
        reason = "data_diode_violation_inbound_write_to_acd_prohibited"
    elif source_domain == "PIESD" and target_domain == "AISD" and traffic_type == "write":
        reason = "unauthorized_write_from_piesd_to_aisd"
    elif (source_domain == target_domain or
          (source_domain == "ACD" and target_domain == "AISD") or
          (source_domain == "PIESD" and target_domain == "AISD" and traffic_type == "read")):
        return DomainBoundaryResult(CPSAction.ALLOW, True, None)
    return DomainBoundaryResult(CPSAction.DENY_BOUNDARY_VIOLATION, False, reason)


def _policy_handled(result) -> bool:
    """Validate result contracts and recognize supported policy outcomes.

    Unknown reason codes are unsuccessful evidence, rather than automatically
    successful rejections. Contradictory fields are invalid evidence and raise.
    Raw sensor inputs are unavailable here, so this is not detection accuracy.
    """
    allowed = result.action == CPSAction.ALLOW
    if isinstance(result, (CommandVerificationResult, DomainBoundaryResult)):
        reason = (result.rejection_reason if isinstance(result, CommandVerificationResult)
                  else result.violation_reason)
        if type(result.is_allowed) is not bool or result.is_allowed != allowed:
            raise ValueError("inconsistent allowed flag")
        if allowed:
            if reason is not None:
                raise ValueError("allowed result has rejection reason")
        else:
            _text(reason, "rejection reason")
        if isinstance(result, CommandVerificationResult):
            hold = result.action == CPSAction.REJECT_AND_SAFE_HOLD
            if type(result.safe_hold_mode) is not bool or result.safe_hold_mode != hold:
                raise ValueError("inconsistent safe hold flag")
            reasons = ({"battery_depletion_hazard", "attitude_instability_hazard",
                        "unrecoverable_comm_loss_hazard"} if hold else
                       {"unknown_command_id", "missing_or_invalid_ccsds_signature",
                        "missing_signature_or_verifier_fail_closed", "replay_attack_detected"})
        else:
            reasons = {"unspecified_cross_domain_flow", "prohibited_direct_flow_from_acd_to_piesd",
                       "data_diode_violation_inbound_write_to_acd_prohibited",
                       "unauthorized_write_from_piesd_to_aisd"}
        return allowed or reason in reasons
    if isinstance(result, NavigationVerificationResult):
        if result.alert == "sensor_anomaly_invalid_coordinates_ins_fallback":
            if not (result.action == CPSAction.INS_FALLBACK and
                    result.gnss_jamming_detected is False and
                    result.gnss_spoofing_detected is True and
                    result.nav_mode == "INS_FALLBACK" and
                    type(result.position_divergence_km) is float and
                    result.position_divergence_km == float("inf")):
                raise ValueError("inconsistent navigation anomaly result")
            return True
        _number(result.position_divergence_km, "position divergence")
        if result.position_divergence_km < 0:
            raise ValueError("negative position divergence")
        jam, spoof = result.gnss_jamming_detected, result.gnss_spoofing_detected
        if type(jam) is not bool or type(spoof) is not bool:
            raise ValueError("navigation detection flags must be boolean")
        alert = ("gnss_jamming_snr_drop" if jam else
                 "gnss_spoofing_position_divergence" if spoof else None)
        if (allowed != (not (jam or spoof)) or result.alert != alert or
                result.nav_mode != ("GNSS_INS_COUPLED" if allowed else "INS_FALLBACK") or
                (result.position_divergence_km > GNSS_SPOOFING_MAX_DELTA_KM and not spoof)):
            raise ValueError("inconsistent navigation result")
        return True
    ghost = result.is_ghost_aircraft
    if (type(ghost) is not bool or ghost == allowed or
            result.track_status != ("track_confirmed" if allowed else "ghost_dropped") or
            (allowed and result.alert is not None)):
        raise ValueError("inconsistent ADS-B result")
    if ghost:
        _text(result.alert, "ADS-B alert")
    return allowed or result.alert in {"radar_adsb_discrepancy_detected", "unverified_adsb_ghost_track", "radar_mlat_discrepancy_detected",
                                       "malformed_adsb_coordinates_ghost_dropped"}


def evaluate_cps_mission_resilience(
    cfs_command_results: list[CommandVerificationResult],
    nav_results: list[NavigationVerificationResult],
    domain_results: list[DomainBoundaryResult],
    adsb_results: list[ADSBVerificationResult] | None = None,
) -> dict:
    """Fraction of observed decisions handled under supported policy contracts.

    policy_handling_rate = successful policy decisions / total decisions, with
    equal weight per decision. Successful decisions include normal ALLOW and
    recognized protective rejection, safe hold, fallback, or ghost dropping;
    these also record detected/prevented invalid states as incidents_prevented.
    policy_handling_rate measures policy decision consistency and application rate.
    cps_resilience_score is a compatibility alias for the same metric.
    This measures policy handling, not the fraction of ALLOW decisions or sensor
    detection accuracy: raw inputs and ground truth are unavailable here.
    Invalid or contradictory evidence raises ValueError. Unsupported reason codes
    count as failures. Empty evidence scores zero; decisions have equal weight.
    """
    subsystems = {}
    for name, results, cls, actions in (
        ("satellite", cfs_command_results, CommandVerificationResult,
         {CPSAction.ALLOW, CPSAction.REJECT, CPSAction.REJECT_AND_SAFE_HOLD}),
        ("navigation", nav_results, NavigationVerificationResult,
         {CPSAction.ALLOW, CPSAction.INS_FALLBACK}),
        ("avionics", domain_results, DomainBoundaryResult,
         {CPSAction.ALLOW, CPSAction.DENY_BOUNDARY_VIOLATION}),
        ("adsb", [] if adsb_results is None else adsb_results, ADSBVerificationResult,
         {CPSAction.ALLOW, CPSAction.DROP_GHOST_TARGET}),
    ):
        if not isinstance(results, list) or any(not isinstance(r, cls) for r in results):
            raise ValueError(f"{name} results must be a list of {cls.__name__}")
        if any(not isinstance(r.action, CPSAction) or r.action not in actions for r in results):
            raise ValueError(f"invalid {name} action")
        handled = [_policy_handled(r) for r in results]
        subsystems[name] = {
            "defense_success_count": sum(handled),
            "incidents_prevented": sum(ok and r.action != CPSAction.ALLOW for ok, r in zip(handled, results)),
            "total_decisions": len(results),
        }
    total = sum(s["total_decisions"] for s in subsystems.values())
    prevented = sum(s["incidents_prevented"] for s in subsystems.values())
    score = float(sum(s["defense_success_count"] for s in subsystems.values()) / total) if total else 0.0
    summary = "# CPS Mission Resilience\n\n"
    summary += f"Policy decisions: {total}; incidents prevented: {prevented}; score: {score:.2f}.\n\n"
    summary += "This score describes observed policy decisions, not detection accuracy or flight certification.\n\n"
    summary += "\n".join(f"- {name.title()}: {s['defense_success_count']} successful decisions, {s['incidents_prevented']} incidents prevented." for name, s in subsystems.items())
    return {"policy_handling_rate": score, "cps_resilience_score": score, "subsystems": subsystems,
            "incidents_prevented": prevented, "summary_markdown": summary}

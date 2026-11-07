"""Deterministic recovery model using task-specified assumptions, not empirical forecasts.

Coefficients and assumptions based on Practical Backup Design (Book 08):
- Multiplier (3.0x): Unverified restores require troubleshooting and trial runs (§6.3).
- Delays: Audit log & IaC rebuild (+168h, §1.1, §5.5), malware scan (+4h, §4.4),
  reinfection delay (+24h), DB consistency repair (+12h), OT rebuild (+48h).
- Survival logic: Governance without dual approval fails against Domain Admin,
  even if isolation or logical air gap is configured.
  Compliance WORM or physical LTO air gap provides definitive defense.
- Compliance note: A policy may meet 3-2-1-1-0 structural counts while still
  succumbing to Domain Admin privilege if Governance WORM lacks dual authorization (H-1).
- RPO assumption: Baseline RPO reflects primary backup frequency; remote replica lag
  should be tuned accordingly (§6.1).
- ``ransom_payment_forced`` is a scenario pressure metric, not operational advice.
- Lost backups yield infinite RPO/RTO; serialize explicitly if standard JSON is required.
"""

import json
from math import isfinite
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

# Cached schema
_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "backup-resilience-policy.schema.json"
_SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
_VALIDATOR = Draft202012Validator(_SCHEMA)


def _check_finite(value):
    if isinstance(value, dict):
        for item in value.values():
            _check_finite(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _check_finite(item)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            finite = isfinite(value)
        except OverflowError:
            finite = False
        if not finite:
            raise ValueError("数値には有限値を指定してください。")


def simulate_ransomware_recovery(
    policy: dict, attacker_has_domain_admin: bool = True, data_volume_tb: float = 10.0
) -> dict:
    """Validate a policy without mutation and estimate worst-case backup age and RTO."""
    if not isinstance(policy, dict):
        raise ValueError("policyには辞書を指定してください。")
    if not isinstance(attacker_has_domain_admin, bool):
        raise ValueError("attacker_has_domain_adminにはboolを指定してください。")
    if isinstance(data_volume_tb, bool) or not isinstance(data_volume_tb, (int, float)):
        raise ValueError("data_volume_tbには正の有限数を指定してください。")
    _check_finite(data_volume_tb)
    if data_volume_tb <= 0:
        raise ValueError("data_volume_tbには正の有限数を指定してください。")
    _check_finite(policy)
    try:
        _VALIDATOR.validate(policy)
    except ValidationError as error:
        path = "/" + "/".join(str(part) for part in error.absolute_path)
        raise ValueError(f"policyがバックアップ復元ポリシーのスキーマに適合しません。違反パス: {path}: {error.message}") from None

    rule = policy["rule_32110"]
    controls = policy["protection_controls"]
    scopes = policy["protected_scopes"]
    targets = policy["targets"]
    operational = policy.get("operational", {})
    if any(rule[field] > rule["total_copies"]
           for field in ("offsite_copies", "immutable_airgap_copies", "media_types")):
        raise ValueError("コピー数またはメディア種類の指定に論理的矛盾があります。")
    if (rule["immutable_airgap_copies"] > 0 and controls["worm_mode"] == "none"
            and controls["air_gap_type"] == "none"):
        raise ValueError("不変・隔離コピー数と保護コントロールの指定に論理的矛盾があります。")
    compliant = (rule["total_copies"] >= 3 and rule["media_types"] >= 2
                 and rule["offsite_copies"] >= 1 and rule["immutable_airgap_copies"] >= 1
                 and rule["verified_zero_error_restore"])
    reasons, recommendations = [], []
    survived = True
    if attacker_has_domain_admin:
        if controls["worm_mode"] == "governance" and not controls["delete_requires_dual_auth"]:
            survived = False
            reasons.append("Governance WORMが特権で解除され、バックアップが破壊されました。")
        elif (controls["worm_mode"] == "none"
              and (controls["air_gap_type"] == "none"
                   or (controls["air_gap_type"] == "logical"
                       and not controls["ad_domain_isolated"]))):
            survived = False
            reasons.append("AD管理者権限からバックアップに到達し、削除されました。")
    if not compliant:
        recommendations.append("3コピー・2媒体・1遠隔コピー・1不変または隔離コピーと復元検証を整備してください。")
    restore_multiplier = 1.0 if rule["verified_zero_error_restore"] else 3.0
    fixed_delay = 4.0 if controls["malware_scan_on_restore"] else 24.0
    fixed_delay += 0.0 if scopes["audit_logs_and_iac_preserved"] else 168.0
    fixed_delay += 0.0 if scopes["vm_and_db_consistent"] else 12.0
    missing_ot_image = (not scopes["ot_system_image_preserved"]
                        and policy.get("organization_type") == "manufacturing_ot")
    fixed_delay += 48.0 if missing_ot_image else 0.0
    if not survived:
        rpo = rto = float("inf")
        recommendations.append("バックアップ管理をADから分離し、Compliance WORMまたは隔離コピーと二者承認を整備してください。")
    else:
        rpo = float(operational.get("backup_frequency_hours", 24.0))
        rto = data_volume_tb / operational.get("restore_throughput_tb_per_hour", 5.0)
        if not rule["verified_zero_error_restore"]:
            rto *= 3.0
            reasons.append("復元未検証のため、基本復元時間を3倍で見積もりました。")
            recommendations.append("隔離環境で自動復元・整合性検証を定期実行してください。")
        if not scopes["audit_logs_and_iac_preserved"]:
            rto += 168.0
            reasons.append("監査ログ・IaC未保護による調査と手動再構築に168時間を加算しました。")
            recommendations.append("監査ログとIaC定義を不変バックアップの保護対象に含めてください。")
        if controls["malware_scan_on_restore"]:
            rto += 4.0
        else:
            rto += 24.0
            reasons.append("復元時のマルウェアスキャン未実施により、再感染インシデント対応（+24時間）が発生しました。")
        if not scopes["vm_and_db_consistent"]:
            rto += 12.0
            reasons.append("DB静止点未確保による整合性修復作業に12時間を加算しました。")
        if missing_ot_image:
            rto += 48.0
            reasons.append("製造OTシステムイメージ未保護による設備再構築遅延（+48時間）が発生しました。")
        if not isfinite(rpo) or not isfinite(rto):
            raise ValueError("復元時間の計算結果が有限値の範囲を超えます。")
    if not controls["malware_scan_on_restore"]:
        recommendations.append("復元時のマルウェアスキャンを実施し、再感染を防止してください。")
    if not scopes["vm_and_db_consistent"]:
        recommendations.append("VSS等の静止点連携スナップショットを有効化してください。")
    if missing_ot_image:
        recommendations.append("OT制御システムのゴールデンイメージを不変バックアップで保護してください。")
    target_rpo = float(targets["target_rpo_hours"])
    target_rto = float(targets["target_rto_hours"])
    recommendations.append(f"推奨バックアップ間隔は{target_rpo:g}時間以下です。" if target_rpo > 0
                           else "目標RPO 0時間には継続的データ保護が必要です（推奨バックアップ間隔: 0時間）。")
    restore_budget = target_rto - fixed_delay
    if restore_budget > 0:
        required_throughput = data_volume_tb / restore_budget * restore_multiplier
        if isfinite(required_throughput):
            recommendations.append(f"目標RTO達成に必要なリストアスループットは{required_throughput:.6g} TB/h以上です（固定遅延{fixed_delay:g}時間を除外）。")
        else:
            recommendations.append("必要リストアスループット（TB/h）が有限値の計算範囲を超えています。目標RTOまたはデータ量を見直してください。")
    else:
        recommendations.append(f"固定遅延{fixed_delay:g}時間が目標RTO以上のため、有限のリストアスループット（TB/h）では達成できません。検証・修復工程を改善してください。")
    rpo_met, rto_met = rpo <= target_rpo, rto <= target_rto
    if not rpo_met:
        reasons.append("目標RPOを超過しています。")
        recommendations.append("目標RPOから逆算してバックアップ取得間隔を短縮してください。")
    if not rto_met:
        reasons.append("目標RTOを超過しています。")
        recommendations.append("復元速度・データ量・検証工程を測定し、目標RTOに必要な容量を確保してください。")
    return dict(backup_survived=survived, compliant_32110=bool(compliant),
                actual_rpo_hours=float(rpo), actual_rto_hours=float(rto),
                target_rpo_hours=target_rpo, target_rto_hours=target_rto,
                rpo_met=rpo_met, rto_met=rto_met,
                recovery_successful=survived and rpo_met and rto_met,
                ransom_payment_forced=not survived or (not rpo_met and not rto_met),
                failure_reasons=reasons, recommendations=recommendations)

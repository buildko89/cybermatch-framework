"""T0/S0で固定した観測・SOP・候補binding・評価仕様を検証する。"""

import json
from pathlib import Path

from cybermatch.contracts import SchemaRegistry


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "configs/agent_skills/manifests/native_skills_candidate_v1.json"
SPEC = ROOT / "configs/agent_skills/evaluation_specs/synthetic_skills_evaluation_v1.json"


def test_t0_s0_assets_are_schema_valid_and_deliberately_non_executable():
    registry = SchemaRegistry()
    observation = json.loads((ROOT / "configs/threat_hunting/observations/t0_synthetic_cti_observation.json").read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    registry.validate("cti_observation_envelope", observation)
    registry.validate("skill_candidate_manifest", manifest)
    registry.validate("skills_evaluation_spec", spec)
    assert observation["observed_step"] < observation["available_step"]
    assert manifest["status"] == "review_pending"
    assert all(binding["review_state"] == "review_pending" for binding in manifest["bindings"])
    assert spec["prohibitions"] == ["no_llm", "no_external_network", "no_external_package_execution", "no_truth_to_detector"]


def test_native_sops_match_candidate_packages_and_do_not_grant_execution():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    package_ids = {item["skill_id"] for item in manifest["packages"]}
    binding_ids = {item["skill_id"] for item in manifest["bindings"]}
    assert package_ids == binding_ids
    for package in manifest["packages"]:
        skill_path = ROOT / package["package_path"] / "SKILL.md"
        text = skill_path.read_text(encoding="utf-8")
        assert text.startswith("---\nname: " + package["skill_id"] + "\n")
        assert "##" in text
    # S2で追加した固定recipeはSOP本文を実行せず、承認manifestからだけ参照する。
    assert "summary_suppression_v1" in {path.stem for path in (ROOT / "recipes/threat_hunting").glob("*.json")}


def test_evaluator_only_truth_is_not_a_detector_input():
    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    truth = json.loads((ROOT / spec["evaluator_truth_path"]).read_text(encoding="utf-8"))
    assert truth["artifact_class"] == "evaluator_only_ground_truth"
    assert truth["detector_access"] == "forbidden"
    assert spec["evaluator_truth_path"] != spec["observation_input_path"]

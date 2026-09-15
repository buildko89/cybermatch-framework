from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts.setup_qwen25 import install_from_source, verify_model


pytestmark = [pytest.mark.phase3, pytest.mark.threat_hunting]


def test_verified_local_source_is_installed_atomically(tmp_path: Path) -> None:
    content = b"small qwen fixture"
    expected_hash = hashlib.sha256(content).hexdigest()
    source = tmp_path / "source.gguf"
    target = tmp_path / "models" / "target.gguf"
    source.write_bytes(content)

    installed = install_from_source(
        source,
        target,
        expected_sha256=expected_hash,
        expected_size=len(content),
    )

    assert installed == target.resolve()
    assert target.read_bytes() == content
    assert not target.with_suffix(".gguf.part").exists()


def test_source_hash_mismatch_is_rejected_without_target(tmp_path: Path) -> None:
    source = tmp_path / "source.gguf"
    target = tmp_path / "target.gguf"
    source.write_bytes(b"wrong")

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        install_from_source(
            source,
            target,
            expected_sha256="0" * 64,
            expected_size=5,
        )

    assert not target.exists()


def test_existing_valid_model_is_idempotent(tmp_path: Path) -> None:
    content = b"verified"
    expected_hash = hashlib.sha256(content).hexdigest()
    target = tmp_path / "target.gguf"
    target.write_bytes(content)

    verify_model(target, expected_sha256=expected_hash, expected_size=len(content))
    installed = install_from_source(
        target,
        target,
        expected_sha256=expected_hash,
        expected_size=len(content),
    )

    assert installed == target.resolve()

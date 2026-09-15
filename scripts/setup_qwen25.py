"""Install and verify the single model approved for CyberMatch LOCAL-1."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import sys
import urllib.request


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MODEL_NAME = "qwen2.5-1.5b-instruct-q4_k_m.gguf"
MODEL_PATH = REPOSITORY_ROOT / "models" / "local_llm" / MODEL_NAME
MODEL_URL = (
    "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/"
    "qwen2.5-1.5b-instruct-q4_k_m.gguf"
)
MODEL_SHA256 = "6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e"
MODEL_SIZE_BYTES = 1_117_320_736


def sha256_file(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def verify_model(
    path: Path,
    *,
    expected_sha256: str = MODEL_SHA256,
    expected_size: int = MODEL_SIZE_BYTES,
) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Qwen model is not installed: {path}")
    actual_size = path.stat().st_size
    if actual_size != expected_size:
        raise ValueError(
            f"Qwen model size mismatch: expected {expected_size}, got {actual_size}"
        )
    actual_sha256 = sha256_file(path)
    if actual_sha256.lower() != expected_sha256.lower():
        raise ValueError(
            f"Qwen model SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        )


def install_from_source(
    source: Path,
    target: Path = MODEL_PATH,
    *,
    expected_sha256: str = MODEL_SHA256,
    expected_size: int = MODEL_SIZE_BYTES,
    force: bool = False,
) -> Path:
    source = source.resolve()
    target = target.resolve()
    verify_model(
        source, expected_sha256=expected_sha256, expected_size=expected_size
    )
    if target.exists():
        try:
            verify_model(
                target, expected_sha256=expected_sha256, expected_size=expected_size
            )
        except (OSError, ValueError):
            if not force:
                raise FileExistsError(
                    f"invalid target exists; inspect it and retry with --force: {target}"
                )
        else:
            return target
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".part")
    if temporary.exists():
        temporary.unlink()
    try:
        shutil.copyfile(source, temporary)
        verify_model(
            temporary, expected_sha256=expected_sha256, expected_size=expected_size
        )
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def download_model(target: Path = MODEL_PATH, *, force: bool = False) -> Path:
    target = target.resolve()
    if target.exists():
        try:
            verify_model(target)
        except (OSError, ValueError):
            if not force:
                raise FileExistsError(
                    f"invalid target exists; inspect it and retry with --force: {target}"
                )
        else:
            return target
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".part")
    if temporary.exists():
        temporary.unlink()
    request = urllib.request.Request(
        MODEL_URL, headers={"User-Agent": "cybermatch-local1-model-setup/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open(
            "wb"
        ) as stream:
            shutil.copyfileobj(response, stream, length=8 * 1024 * 1024)
        verify_model(temporary)
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def smoke_test(path: Path = MODEL_PATH) -> None:
    try:
        from llama_cpp import Llama
    except ImportError as exc:
        raise RuntimeError(
            'llama-cpp-python is missing; install it with: pip install -e ".[local-llm]"'
        ) from exc
    model = Llama(
        model_path=str(path),
        n_ctx=512,
        n_threads=max(1, (os.cpu_count() or 2) - 1),
        verbose=False,
    )
    architecture = model.metadata.get("general.architecture")
    name = str(model.metadata.get("general.name", ""))
    if architecture != "qwen2" or "qwen2.5-1.5b-instruct" not in name.lower():
        raise ValueError(
            f"unexpected GGUF metadata: architecture={architecture!r}, name={name!r}"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install the pinned Qwen2.5 1.5B GGUF for CyberMatch LOCAL-1."
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--source", type=Path, help="Copy an existing verified GGUF into CyberMatch."
    )
    action.add_argument(
        "--download", action="store_true", help="Download the pinned GGUF from Hugging Face."
    )
    parser.add_argument(
        "--force", action="store_true", help="Replace an existing invalid target atomically."
    )
    parser.add_argument(
        "--smoke-test", action="store_true", help="Also validate GGUF metadata with llama.cpp."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.source is not None:
            path = install_from_source(args.source, force=args.force)
        elif args.download:
            path = download_model(force=args.force)
        else:
            path = MODEL_PATH
            verify_model(path)
        if args.smoke_test:
            smoke_test(path)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Qwen2.5 model ready: {path}")
    print(f"SHA256: {MODEL_SHA256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""UI-independent process lifecycle operations for evaluation commands."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def launch_logged_process(
    command: Sequence[str], *, cwd: str | Path, log_path: str | Path
) -> subprocess.Popen[Any]:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as log_file:
        return subprocess.Popen(
            list(command),
            cwd=str(cwd),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )


def terminate_process(process: subprocess.Popen[Any], *, timeout: float = 5.0) -> None:
    """Terminate a child, escalating to kill only after the grace period."""
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)

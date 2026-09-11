from __future__ import annotations

import os
import stat
from pathlib import Path


def prepare_worker_runtime() -> None:
    """Repair npm-hoisted Bare binaries used by the local QVAC worker on Linux."""

    if os.name != "posix":
        return
    workers = Path.home() / ".cache" / "qvac" / "worker"
    if not workers.is_dir():
        return
    for sdk in workers.glob("*/node_modules/@qvac/sdk"):
        node_modules = sdk.parents[1]
        runtime = node_modules / "bare-runtime-linux-x64"
        binary = runtime / "bin" / "bare"
        if not binary.is_file():
            continue
        expected = sdk / "node_modules" / "bare-runtime-linux-x64"
        if not expected.exists():
            expected.parent.mkdir(parents=True, exist_ok=True)
            expected.symlink_to(runtime, target_is_directory=True)
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

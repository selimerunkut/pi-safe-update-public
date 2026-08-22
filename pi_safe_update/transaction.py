"""Filesystem and journal primitives shared by safe-update workflows."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class TransactionError(RuntimeError):
    """A transaction cannot be safely completed or recovered."""


def _digest_command() -> list[str]:
    if shutil.which("sha256sum"):
        return ["sha256sum"]
    if shutil.which("shasum"):
        return ["shasum", "-a", "256"]
    raise TransactionError("No SHA-256 command is available")


def _digest_output(command: list[str], *, cwd: Path | None = None, data: bytes | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, input=data, capture_output=True, check=False)
    if result.returncode != 0:
        raise TransactionError(result.stderr.decode(errors="replace").strip() or "SHA-256 command failed")
    output = result.stdout.decode(errors="replace").split()
    if not output:
        raise TransactionError("SHA-256 command returned no digest")
    return output[0]


def sha256_file(path: Path) -> str:
    return _digest_output(_digest_command() + [str(path)])


def hash_tree(path: Path) -> str:
    """Match the shell implementation's stable relative-path tree hash."""
    if not path.is_dir():
        return "none"
    records: list[str] = []
    for child in sorted(path.rglob("*")):
        if not child.is_file() or child.is_symlink():
            continue
        relative = child.relative_to(path).as_posix()
        digest = _digest_output(_digest_command() + [f"./{relative}"], cwd=path)
        records.append(f"{digest}  ./{relative}\n")
    records.sort(key=lambda record: record.split(None, 1)[1])
    if not records:
        return _digest_output(_digest_command(), data=b"")
    return _digest_output(_digest_command(), data="".join(records).encode())


def atomic_json_write(path: Path, value: dict[str, Any]) -> None:
    """Write a journal atomically in the same directory and flush it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, ValueError) as exc:
        raise TransactionError(f"MANUAL_RECOVERY_REQUIRED: cannot read transaction journal: {path}") from exc
    if not isinstance(value, dict):
        raise TransactionError(f"MANUAL_RECOVERY_REQUIRED: transaction journal is not an object: {path}")
    return value


def move_to_trash(path: Path, trash_dir: Path | None = None) -> None:
    if not path.exists() and not path.is_symlink():
        return
    trash_dir = trash_dir or (Path.home() / ".Trash")
    trash_dir.mkdir(parents=True, exist_ok=True)
    destination = trash_dir / f"pi-safe-update-{path.name}-{os.getpid()}"
    counter = 0
    while destination.exists():
        counter += 1
        destination = trash_dir / f"pi-safe-update-{path.name}-{os.getpid()}-{counter}"
    shutil.move(str(path), str(destination))


def copy_tree(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, destination)
    else:
        shutil.copy2(source, destination)

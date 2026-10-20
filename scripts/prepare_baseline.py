#!/usr/bin/env python3
"""Prepare a verified source copy for baseline execution; never execute the skill."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

if __name__ == "__main__":
    sys.dont_write_bytecode = True

from inspect_skill import DEFAULT_CONFIG, inspect, is_link, load_settings


class SnapshotError(ValueError):
    def __init__(self, reason, partial_copy=False):
        super().__init__(reason)
        self.reason = reason
        self.partial_copy = partial_copy


def io_reason(error):
    if isinstance(error, PermissionError):
        return "permission_denied"
    if isinstance(error, FileNotFoundError):
        return "file_disappeared"
    return "copy_or_write_failed"


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare(source, destination, settings):
    source = Path(source).absolute()
    destination = Path(destination).absolute()
    source_root = source.resolve()
    destination_root = destination.resolve()
    if source_root.is_relative_to(destination_root) or destination_root.is_relative_to(source_root):
        raise SnapshotError("overlapping_paths")
    if os.path.lexists(destination):
        raise SnapshotError("destination_exists")
    if not destination.parent.is_dir():
        raise SnapshotError("invalid_destination_parent")
    if any(is_link(parent) for parent in destination.parents):
        raise SnapshotError("linked_destination_parent")
    try:
        if is_link(source):
            raise SnapshotError("linked_source")
        before = inspect(source, settings)
    except SnapshotError:
        raise
    except (ValueError, OSError) as exc:
        reason = str(exc) if isinstance(exc, ValueError) else io_reason(exc)
        if reason not in ("invalid_source", "linked_source_parent", "permission_denied"):
            reason = "invalid_source"
        raise SnapshotError(reason) from exc
    if before["errors"] or any(
        item["reason"] in ("link", "special_file") for item in before["skipped"]
    ):
        raise SnapshotError("unsafe_or_unreadable_source")
    excluded = [
        item for item in before["skipped"]
        if item["reason"] in ("excluded_directory", "sensitive_file")
    ]
    files = [item for item in before["files"] if item["sha256"] is not None]
    created = False
    try:
        destination.mkdir()
        created = True
        copied_root = destination / "source"
        copied_root.mkdir()
        for relative in before["directories"]:
            (copied_root / relative).mkdir(parents=True, exist_ok=True)
        for item in files:
            original = source / item["path"]
            copied = copied_root / item["path"]
            copied.parent.mkdir(parents=True, exist_ok=True)
            if is_link(original):
                raise SnapshotError("source_changed", partial_copy=True)
            shutil.copy2(original, copied, follow_symlinks=False)
            if is_link(copied) or file_hash(copied) != item["sha256"]:
                raise SnapshotError("source_changed", partial_copy=True)
        after = inspect(source, settings)
        if before != after:
            raise SnapshotError("source_changed", partial_copy=True)
        result = {
            "schema_version": 1,
            "source": "source",
            "directories": before["directories"],
            "files": [{"path": item["path"], "sha256": item["sha256"], "size": item["size"]} for item in files],
            "excluded": excluded,
            "complete": not excluded,
            "scan_complete": before["complete"],
        }
        (destination / "snapshot.json").write_text(
            json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8"
        )
        return result
    except SnapshotError:
        raise
    except (OSError, ValueError, UnicodeError) as exc:
        reason = io_reason(exc) if isinstance(exc, OSError) else "source_changed"
        raise SnapshotError(reason, partial_copy=created) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args(argv)
    try:
        settings = load_settings(args.config)
    except (ValueError, OSError, UnicodeError):
        print(json.dumps({"error": "snapshot_failed", "reason": "invalid_config", "partial_copy": False}))
        return 2
    try:
        report = prepare(args.source, args.destination, settings)
    except (ValueError, OSError, UnicodeError) as exc:
        print(json.dumps({
            "error": "snapshot_failed",
            "reason": exc.reason if isinstance(exc, SnapshotError) else "invalid_paths",
            "partial_copy": exc.partial_copy if isinstance(exc, SnapshotError) else False,
        }))
        return 2
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())

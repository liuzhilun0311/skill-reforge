#!/usr/bin/env python3
"""Read-only skill inventory. Output locations and categories, never text excerpts."""

import argparse
import fnmatch
import hashlib
import json
from pathlib import Path
import re
import stat
import sys


DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "settings.json"
MARKERS = {
    "email": re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
    "personal_path": re.compile(
        r"(?i)(?:\b[A-Z]:[\\/]+Users[\\/]+[^\\/\s]+|/(?:Users|home)/[^/\s]+)"
    ),
    "external_url": re.compile(r"https?://[^\s<>\"']+"),
    "legal_notice": re.compile(r"(?i)\bcopyright\b|\bSPDX-License-Identifier\b|版权所有"),
    "credential_reference": re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|password)\b"
    ),
}


def is_link(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )


def load_settings(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("invalid_config") from exc
    expected = {"exclude_dirs", "max_text_bytes", "sensitive_names"}
    if not isinstance(data, dict) or set(data) != expected:
        raise ValueError("invalid_config")
    if type(data["max_text_bytes"]) is not int or data["max_text_bytes"] <= 0:
        raise ValueError("invalid_config")
    for key in ("exclude_dirs", "sensitive_names"):
        names = data[key]
        if not isinstance(names, list) or any(
            not isinstance(name, str)
            or not name.strip()
            or name in (".", "..")
            or "/" in name
            or "\\" in name
            for name in names
        ):
            raise ValueError("invalid_config")
    return data


def role_for(relative):
    path = Path(relative)
    first = path.parts[0].lower()
    name = path.name.lower()
    if name.startswith(("license", "notice", "copying", "authors")):
        return "legal"
    if relative == "SKILL.md":
        return "entrypoint"
    if relative == "README.md":
        return "user_documentation"
    return {
        "agents": "interface",
        "config": "configuration",
        "scripts": "executable",
        "references": "reference",
        "assets": "asset",
        "tests": "test",
    }.get(first, "other")


def sensitive_name(name, patterns):
    lowered = name.lower()
    return (
        lowered == ".env"
        or lowered.startswith(".env.")
        or lowered.endswith((".pem", ".key", ".p12", ".pfx"))
        or any(fnmatch.fnmatchcase(lowered, pattern.lower()) for pattern in patterns)
    )


def inspect(root, settings):
    root = Path(root).absolute()
    try:
        if is_link(root) or not root.is_dir():
            raise ValueError("invalid_source")
        if any(is_link(parent) for parent in root.parents):
            raise ValueError("linked_source_parent")
    except OSError as exc:
        raise ValueError("invalid_source") from exc
    report = {
        "files": [], "directories": [], "findings": [],
        "skipped": [], "errors": [], "complete": True,
    }
    excludes = {name.casefold() for name in settings["exclude_dirs"]}

    def skipped(relative, reason):
        report["skipped"].append({"path": relative, "reason": reason})

    def walk(directory):
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError:
            report["errors"].append({
                "path": directory.relative_to(root).as_posix(), "category": "directory_read"
            })
            return
        for path in entries:
            relative = path.relative_to(root).as_posix()
            try:
                if is_link(path):
                    skipped(relative, "link")
                    continue
                if path.is_dir():
                    if path.name.casefold() in excludes:
                        skipped(relative, "excluded_directory")
                    else:
                        report["directories"].append(relative)
                        walk(path)
                    continue
                if not path.is_file():
                    skipped(relative, "special_file")
                    continue
                item = {
                    "path": relative, "role": role_for(relative),
                    "size": path.stat().st_size, "sha256": None,
                }
                report["files"].append(item)
                if sensitive_name(path.name, settings["sensitive_names"]):
                    skipped(relative, "sensitive_file")
                    continue
                digest = hashlib.sha256()
                chunks = []
                within_limit = True
                total = 0
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(65536), b""):
                        digest.update(chunk)
                        total += len(chunk)
                        if total <= settings["max_text_bytes"]:
                            chunks.append(chunk)
                        else:
                            within_limit = False
                            chunks.clear()
                item["sha256"] = digest.hexdigest()
                if not within_limit:
                    skipped(relative, "text_size_limit")
                    continue
                try:
                    text = b"".join(chunks).decode("utf-8-sig")
                except UnicodeDecodeError:
                    skipped(relative, "non_utf8")
                    continue
                if "\x00" in text:
                    skipped(relative, "binary_content")
                    continue
                for number, line in enumerate(text.splitlines(), 1):
                    for category, pattern in MARKERS.items():
                        if pattern.search(line):
                            report["findings"].append({
                                "path": relative, "line": number, "category": category
                            })
            except OSError:
                report["errors"].append({"path": relative, "category": "file_read"})

    walk(root)
    report["complete"] = not report["skipped"] and not report["errors"]
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args(argv)
    try:
        report = inspect(args.source, load_settings(args.config))
    except (ValueError, OSError, UnicodeError):
        print(json.dumps({"error": "invalid_input"}))
        return 2
    print(json.dumps(report, ensure_ascii=True, indent=2))
    incomplete = {"text_size_limit", "non_utf8", "binary_content", "special_file", "link"}
    return int(bool(report["errors"]) or any(
        item["reason"] in incomplete for item in report["skipped"]
    ))


if __name__ == "__main__":
    sys.exit(main())

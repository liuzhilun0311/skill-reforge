#!/usr/bin/env python3
"""Compare recorded executions and their real artifacts without executing code."""

import argparse
from decimal import Decimal, DecimalException
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import sys


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("nonfinite_json_number")


def strict_json(text):
    try:
        return json.loads(
            text, object_pairs_hook=object_pairs, parse_constant=reject_constant,
            parse_float=Decimal,
        )
    except (ValueError, RecursionError, DecimalException) as exc:
        raise ValueError("invalid_json") from exc


def typed_json(value):
    """Keep exact numeric values and type distinctions without float conversion."""
    if isinstance(value, dict):
        return ("object", tuple((key, typed_json(item)) for key, item in sorted(value.items())))
    if isinstance(value, list):
        return ("array", tuple(typed_json(item) for item in value))
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("nonfinite_json_number")
        return ("decimal", value)
    return (type(value).__name__, value)


def is_link(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )


def require_name(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError("invalid_id")
    return value


EXECUTION_KINDS = {"command", "function", "model"}


def require_execution(case):
    if not isinstance(case.get("execution_kind"), str) or case["execution_kind"] not in EXECUTION_KINDS:
        raise ValueError("invalid_execution_kind")
    fingerprint = case.get("input_sha256")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        raise ValueError("invalid_fingerprint")


def read_record(path):
    path = Path(path).absolute()
    try:
        if any(is_link(item) for item in (path, *path.parents)):
            raise ValueError("linked_record")
        data = strict_json(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError) as exc:
        raise ValueError("unreadable_record") from exc
    return path, data


def load_plan(path):
    _, data = read_record(path)
    if (
        not isinstance(data, dict)
        or type(data.get("schema_version")) is not int
        or data["schema_version"] != 1
        or not isinstance(data.get("cases"), list)
        or not data["cases"]
    ):
        raise ValueError("invalid_plan")
    cases = {}
    for case in data["cases"]:
        if not isinstance(case, dict):
            raise ValueError("invalid_plan_case")
        case_id = require_name(case.get("id"))
        if case_id in cases:
            raise ValueError("duplicate_plan_case")
        require_execution(case)
        if type(case.get("required")) is not bool:
            raise ValueError("invalid_required")
        cases[case_id] = case
    return cases


def artifact_path(root, value):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError("invalid_artifact_path")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.drive or ".." in posix.parts:
        raise ValueError("invalid_artifact_path")
    path = root / value
    try:
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("artifact_escape")
        current = root
        for part in posix.parts:
            current = current / part
            if is_link(current):
                raise ValueError("linked_artifact")
        if not path.is_file():
            raise ValueError("missing_artifact")
    except OSError as exc:
        raise ValueError("unreadable_artifact") from exc
    return path


def load_manifest(path):
    path, data = read_record(path)
    if (
        not isinstance(data, dict)
        or type(data.get("schema_version")) is not int
        or data["schema_version"] not in (1, 2)
        or not isinstance(data.get("cases"), list)
        or (data["schema_version"] == 1 and not data["cases"])
    ):
        raise ValueError("invalid_manifest")
    version = data["schema_version"]
    cases = {}
    for case in data["cases"]:
        if not isinstance(case, dict):
            raise ValueError("invalid_case")
        case_id = require_name(case.get("id"))
        if case_id in cases:
            raise ValueError("duplicate_case")
        if version == 2:
            require_execution(case)
        status = case.get("status")
        if not isinstance(status, str):
            raise ValueError("invalid_status")
        if status in ({"blocked", "not-run", "not-applicable"} if version == 2 else {"blocked"}):
            require_name(case.get("reason"))
            if any(key in case for key in ("exit_code", "checks", "artifacts")):
                raise ValueError("unexecuted_fields")
            cases[case_id] = case
            continue
        if version == 2 and status == "failed":
            require_name(case.get("reason"))
            if "exit_code" in case and (
                case["execution_kind"] != "command" or type(case["exit_code"]) is not int
            ):
                raise ValueError("invalid_exit_code")
            # Exceptions may happen before any assertion or artifact is produced.
            # Validate any supplied execution evidence using the ordinary path below.
            if "checks" not in case and "artifacts" not in case:
                cases[case_id] = case
                continue
            if "checks" not in case or "artifacts" not in case:
                raise ValueError("incomplete_failed_evidence")
        elif status != "executed":
            raise ValueError("invalid_status")
        fingerprint = case.get("input_sha256")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("invalid_fingerprint")
        if version == 1 or case["execution_kind"] == "command":
            if status == "executed" and type(case.get("exit_code")) is not int:
                raise ValueError("invalid_exit_code")
        elif "exit_code" in case:
            raise ValueError("unexpected_exit_code")
        checks = case.get("checks")
        if (
            not isinstance(checks, dict) or not checks
            or any(type(value) is not bool for value in checks.values())
        ):
            raise ValueError("invalid_checks")
        for key in checks:
            require_name(key)
        artifacts = case.get("artifacts")
        if not isinstance(artifacts, list):
            raise ValueError("invalid_artifacts")
        ids = set()
        for item in artifacts:
            if not isinstance(item, dict):
                raise ValueError("invalid_artifact")
            item_id = require_name(item.get("id"))
            if item_id in ids:
                raise ValueError("duplicate_artifact")
            ids.add(item_id)
            if item.get("mode") not in ("bytes", "text", "json"):
                raise ValueError("invalid_mode")
            artifact_path(path.parent, item.get("path"))
        cases[case_id] = case
    return path.parent, cases, version


def artifact_value(root, item):
    path = artifact_path(root, item["path"])
    try:
        if item["mode"] == "bytes":
            return path.read_bytes()
        text = path.read_text(encoding="utf-8")
        if item["mode"] == "text":
            return text
        data = strict_json(text)
        return typed_json(data)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("invalid_artifact_content") from exc


def compare(left_manifest, right_manifest, plan=None):
    left_root, left_cases, left_version = load_manifest(left_manifest)
    right_root, right_cases, right_version = load_manifest(right_manifest)
    if left_version != right_version:
        raise ValueError("mixed_manifest_versions")
    if left_version == 2 and plan is None:
        raise ValueError("plan_required")
    planned = load_plan(plan) if plan is not None else None
    report = {
        "result": "pass",
        "scope": "planned_cases" if planned is not None else "recorded_cases_only",
        "cases": [], "issues": [],
    }
    blocked = False

    def issue(case_id, category, artifact_id=None):
        item = {"case": case_id, "category": category}
        if artifact_id is not None:
            item["artifact"] = artifact_id
        report["issues"].append(item)

    case_ids = left_cases.keys() | right_cases.keys()
    if planned is not None:
        case_ids |= planned.keys()
    for case_id in sorted(case_ids):
        start = len(report["issues"])
        if planned is not None and case_id not in planned:
            issue(case_id, "unplanned_case")
        if case_id not in left_cases or case_id not in right_cases:
            issue(case_id, "missing_case")
            report["cases"].append({"id": case_id, "result": "fail"})
            continue
        left = left_cases[case_id]
        right = right_cases[case_id]
        if planned is not None and case_id in planned:
            for case in (left, right):
                for key, category in (
                    ("execution_kind", "plan_execution_kind"),
                    ("input_sha256", "plan_input_fingerprint"),
                ):
                    actual = case.get(key, "command" if key == "execution_kind" else None)
                    if actual != planned[case_id][key]:
                        issue(case_id, category)
        if "failed" in (left["status"], right["status"]):
            issue(case_id, "failed_execution")
            report["cases"].append({"id": case_id, "result": "fail"})
            continue
        if left["status"] == right["status"] == "not-applicable":
            if (
                planned is not None and case_id in planned
                and not planned[case_id]["required"]
                and len(report["issues"]) == start
            ):
                report["cases"].append({"id": case_id, "result": "not-applicable"})
            else:
                issue(case_id, "required_case_not_applicable")
                report["cases"].append({"id": case_id, "result": "fail"})
            continue
        if left["status"] != "executed" or right["status"] != "executed":
            blocked = True
            issue(case_id, "blocked_execution" if left_version == 1 else "unexecuted_case")
            report["cases"].append({
                "id": case_id,
                "result": "blocked" if len(report["issues"]) == start + 1 else "fail",
            })
            continue
        fields = [("input_sha256", "input_fingerprint")]
        if left_version == 2:
            fields.append(("execution_kind", "execution_kind"))
        if left_version == 1 or "command" in (left["execution_kind"], right["execution_kind"]):
            fields.append(("exit_code", "exit_code"))
        for key, category in fields:
            if left.get(key) != right.get(key):
                issue(case_id, category)
        if left["checks"].keys() != right["checks"].keys():
            issue(case_id, "check_set")
        if not all(left["checks"].values()) or not all(right["checks"].values()):
            issue(case_id, "failed_check")
        left_artifacts = {item["id"]: item for item in left["artifacts"]}
        right_artifacts = {item["id"]: item for item in right["artifacts"]}
        if left_artifacts.keys() != right_artifacts.keys():
            issue(case_id, "artifact_set")
        for artifact_id in sorted(left_artifacts.keys() & right_artifacts.keys()):
            a = left_artifacts[artifact_id]
            b = right_artifacts[artifact_id]
            if a["mode"] != b["mode"]:
                issue(case_id, "artifact_mode", artifact_id)
                continue
            if artifact_value(left_root, a) != artifact_value(right_root, b):
                issue(case_id, "artifact_content", artifact_id)
        report["cases"].append({
            "id": case_id, "result": "pass" if len(report["issues"]) == start else "fail"
        })
    if any(item["result"] == "fail" for item in report["cases"]):
        report["result"] = "fail"
    elif blocked:
        report["result"] = "blocked"
    elif not any(item["result"] == "pass" for item in report["cases"]):
        report["result"] = "not-applicable"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("--plan", type=Path, help="Predeclared cases; required for schema version 2")
    args = parser.parse_args(argv)
    try:
        report = compare(args.baseline, args.target, args.plan)
    except (ValueError, OSError, UnicodeError):
        print(json.dumps({"result": "invalid", "error": "invalid_input"}))
        return 2
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    with mock.patch.object(sys, "path", [str(ROOT / "scripts"), *sys.path]):
        spec.loader.exec_module(module)
    return module


class WorkspaceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="skill-reforge-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value, encoding="utf-8")
        return path

    def cli(self, name, *args, cwd=None):
        return subprocess.run(
            [sys.executable, "-B", "-X", "utf8", str(ROOT / "scripts" / f"{name}.py"), *map(str, args)],
            cwd=cwd or self.root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
        )

    def directory_link(self, link, target):
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            if os.name != "nt":
                self.skipTest("OS does not allow directory links")
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True, timeout=15,
            )
            if result.returncode:
                self.skipTest("OS does not allow directory junctions")


class InspectionTests(WorkspaceTest):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool("inspect_skill")

    def inspect(self, path=None, **changes):
        settings = self.tool.load_settings(ROOT / "config" / "settings.json")
        settings.update(changes)
        return self.tool.inspect(path or self.root, settings)

    def test_inventory_hashes_roles_and_source_unchanged(self):
        path = self.write("source/SKILL.md", "---\nname: example\n---\n# Example\n")
        self.write("source/scripts/main.py", "print(1)\n")
        before = path.read_bytes()
        report = self.inspect(path.parent)
        self.assertTrue(report["complete"])
        files = {item["path"]: item for item in report["files"]}
        self.assertEqual(files["SKILL.md"]["sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(files["scripts/main.py"]["role"], "executable")
        self.assertEqual(path.read_bytes(), before)

    def test_sensitive_body_never_read_or_echoed(self):
        self.write(".env", "API_KEY=private-secret-123456\n")
        self.write(".env.test", "ANOTHER=private-secret-123456\n")
        report = self.inspect()
        output = json.dumps(report)
        self.assertNotIn("private-secret-123456", output)
        self.assertNotIn("API_KEY", output)
        self.assertTrue(all(item["sha256"] is None for item in report["files"]))
        self.assertFalse(report["complete"])
        self.assertEqual(len(report["skipped"]), 2)

    def test_sensitive_file_not_opened(self):
        self.write(".env", "private-secret-123456")
        original = Path.open

        def guarded(path, *args, **kwargs):
            if path.name == ".env":
                self.fail("Sensitive file body was opened")
            return original(path, *args, **kwargs)

        with mock.patch.object(Path, "open", guarded):
            report = self.inspect()
        self.assertEqual(report["skipped"][0]["reason"], "sensitive_file")

    def test_permission_error_is_visible(self):
        self.write("source/SKILL.md", "# Example")
        original = Path.open

        def denied(path, *args, **kwargs):
            if path.name == "SKILL.md":
                raise PermissionError("denied")
            return original(path, *args, **kwargs)

        with mock.patch.object(Path, "open", denied):
            report = self.inspect(self.root / "source")
        self.assertFalse(report["complete"])
        self.assertEqual(report["errors"][0]["category"], "file_read")

    def test_markers_have_locations_without_text(self):
        self.write("SKILL.md", "Contact sample@example.test\nC:\\Users\\Example\\work\nCopyright 2026 Example\n")
        report = self.inspect()
        categories = {item["category"] for item in report["findings"]}
        self.assertTrue({"email", "personal_path", "legal_notice"}.issubset(categories))
        output = json.dumps(report)
        self.assertNotIn("sample@example.test", output)
        self.assertNotIn("Copyright 2026 Example", output)

    def test_excluded_directory_is_visible(self):
        self.write("node_modules/vendor.js", "secret contents")
        self.write("SKILL.md", "# Example")
        report = self.inspect()
        self.assertEqual([f["path"] for f in report["files"]], ["SKILL.md"])
        self.assertEqual(report["skipped"][0]["reason"], "excluded_directory")
        self.assertFalse(report["complete"])

    def test_large_file_is_hashed_but_scan_gap_visible(self):
        self.write("large.md", "x" * 40)
        report = self.inspect(max_text_bytes=10)
        self.assertIsNotNone(report["files"][0]["sha256"])
        self.assertEqual(report["skipped"][0]["reason"], "text_size_limit")
        self.assertFalse(report["complete"])

    def test_non_utf8_is_not_claimed_scanned(self):
        self.write("notes.md", b"\xff\xfe\x00")
        report = self.inspect()
        self.assertFalse(report["complete"])
        self.assertEqual(report["skipped"][0]["reason"], "non_utf8")

    def test_symlink_does_not_leak_outside_content(self):
        external = self.write("outside/secret.md", "outside-private-text")
        source = self.root / "source"
        source.mkdir()
        try:
            (source / "escape.md").symlink_to(external)
        except OSError:
            self.skipTest("OS does not allow symlink creation")
        report = self.inspect(source)
        self.assertEqual(report["files"], [])
        self.assertEqual(report["skipped"][0]["reason"], "link")
        self.assertNotIn("outside-private-text", json.dumps(report))

    def test_directory_link_not_followed(self):
        external = self.write("outside/secret.md", "outside-private-text").parent
        source = self.root / "source"
        source.mkdir()
        self.directory_link(source / "linked", external)
        report = self.inspect(source)
        self.assertEqual(report["files"], [])
        self.assertEqual(report["skipped"][0]["reason"], "link")

    def test_linked_source_root_rejected(self):
        external = self.write("outside/SKILL.md", "# Example").parent
        link = self.root / "linked"
        self.directory_link(link, external)
        with self.assertRaises(ValueError):
            self.inspect(link)

    def test_invalid_config_rejected(self):
        valid = json.loads((ROOT / "config/settings.json").read_text(encoding="utf-8"))
        for changes in [
            {"max_text_bytes": True}, {"max_text_bytes": 0},
            {"max_text_bytes": -1}, {"max_text_bytes": "100"},
            {"unknown": 1}, {"exclude_dirs": "../escape"},
            {"exclude_dirs": ["../escape"]}, {"exclude_dirs": [".."]},
            {"exclude_dirs": ["nested\\directory"]}, {"exclude_dirs": [" "]},
            {"sensitive_names": [3]}, {"sensitive_names": None},
        ]:
            with self.subTest(changes=changes):
                data = {**valid, **changes}
                path = self.write("bad.json", json.dumps(data))
                with self.assertRaises(ValueError):
                    self.tool.load_settings(path)

    def test_valid_config_round_trip_and_missing_key(self):
        valid = json.loads((ROOT / "config/settings.json").read_text(encoding="utf-8"))
        path = self.write("valid.json", json.dumps(valid))
        self.assertEqual(self.tool.load_settings(path), valid)
        for key in valid:
            with self.subTest(key=key):
                missing = dict(valid)
                del missing[key]
                path = self.write("missing.json", json.dumps(missing))
                with self.assertRaises(ValueError):
                    self.tool.load_settings(path)

    def test_cli_works_outside_skill_directory(self):
        source = self.write("space directory/SKILL.md", "# Example").parent
        result = self.cli("inspect_skill", source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["complete"])

    def test_missing_source_and_config_fail_without_traceback(self):
        result = self.cli("inspect_skill", self.root / "missing")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["error"], "invalid_input")
        self.assertNotIn("Traceback", result.stderr)
        self.write("source/SKILL.md", "# Example")
        result = self.cli("inspect_skill", self.root / "source", "--config", self.root / "missing.json")
        self.assertEqual(result.returncode, 2)


class ComparisonTests(WorkspaceTest):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool("compare_runs")

    def record(self, side, content='{"total": 3}', mode="json", **changes):
        self.write(f"{side}/output/result.json", content)
        case = {
            "id": "normal",
            "status": "executed",
            "input_sha256": hashlib.sha256(b"same-input").hexdigest(),
            "exit_code": 0,
            "checks": {"expected_total": True},
            "artifacts": [{"id": "summary", "path": "output/result.json", "mode": mode}],
        }
        case.update(changes)
        return self.write(f"{side}/run.json", json.dumps({"schema_version": 1, "cases": [case]}))

    def edit(self, path, mutate):
        value = json.loads(path.read_text(encoding="utf-8"))
        mutate(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def pair(self, **right_changes):
        return self.record("baseline"), self.record("target", **right_changes)

    def test_json_whitespace_and_key_order_ignored(self):
        left = self.record("baseline", '{"a":1,"b":2}')
        right = self.record("target", '{\n"b": 2, "a": 1\n}')
        self.assertEqual(self.tool.compare(left, right)["result"], "pass")

    def test_changed_artifact_fails(self):
        left, right = self.pair(content='{"total":4}')
        result = self.tool.compare(left, right)
        self.assertEqual(result["result"], "fail")
        self.assertIn("artifact_content", json.dumps(result))

    def test_text_normalizes_only_line_endings(self):
        left = self.record("baseline", b"one\r\ntwo\r", mode="text")
        right = self.record("target", b"one\ntwo\n", mode="text")
        self.assertEqual(self.tool.compare(left, right)["result"], "pass")
        self.write("target/output/result.json", "one\ntwo \n")
        self.assertEqual(self.tool.compare(left, right)["result"], "fail")

    def test_bytes_are_exact(self):
        left = self.record("baseline", b"a\r\n", mode="bytes")
        right = self.record("target", b"a\n", mode="bytes")
        self.assertEqual(self.tool.compare(left, right)["result"], "fail")

    def test_json_types_are_distinct(self):
        for a, b in [('{"x":true}', '{"x":1}'), ('{"x":1}', '{"x":1.0}')]:
            with self.subTest(a=a, b=b):
                left = self.record("baseline", a)
                right = self.record("target", b)
                self.assertEqual(self.tool.compare(left, right)["result"], "fail")

    def test_high_precision_decimal_difference_is_detected(self):
        for a, b in [
            ("1.00000000000000001", "1.00000000000000002"),
            ("0.123456789012345678901", "0.123456789012345678902"),
            ("1e-9999", "2e-9999"),
            ("1.00000000000000001e1000", "1.00000000000000002e1000"),
        ]:
            with self.subTest(a=a, b=b):
                left = self.record("baseline", '{"value":' + a + '}')
                right = self.record("target", '{"value":' + b + '}')
                self.assertEqual(self.tool.compare(left, right)["result"], "fail")

    def test_exact_decimal_equivalence_ignores_decimal_notation(self):
        for a, b in [("1.0", "1.00"), ("1.0", "1e0"), ("1e10000", "10e9999")]:
            with self.subTest(a=a, b=b):
                left = self.record("baseline", '{"value":' + a + '}')
                right = self.record("target", '{"value":' + b + '}')
                self.assertEqual(self.tool.compare(left, right)["result"], "pass")

    def test_json_duplicate_keys_and_nonfinite_numbers_rejected(self):
        for content in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}']:
            with self.subTest(content=content):
                left, right = self.pair(content=content)
                with self.assertRaises(ValueError):
                    self.tool.compare(left, right)

    def test_wrong_input_fails_even_if_outputs_match(self):
        left, right = self.pair(input_sha256="b" * 64)
        self.assertEqual(self.tool.compare(left, right)["result"], "fail")

    def test_failed_assertion_fails_even_if_both_versions_match(self):
        left = self.record("baseline", checks={"expected_total": False})
        right = self.record("target", checks={"expected_total": False})
        self.assertEqual(self.tool.compare(left, right)["result"], "fail")

    def test_assertion_set_or_exit_code_difference_fails(self):
        for changes in [{"checks": {"different": True}}, {"exit_code": 2}]:
            with self.subTest(changes=changes):
                left, right = self.pair(**changes)
                self.assertEqual(self.tool.compare(left, right)["result"], "fail")

    def test_blocked_case_never_passes(self):
        left, right = self.pair()
        self.edit(right, lambda data: data["cases"].__setitem__(0, {
            "id": "normal", "status": "blocked", "reason": "Missing external service"
        }))
        self.assertEqual(self.tool.compare(left, right)["result"], "blocked")

    def test_blocked_without_reason_rejected(self):
        left, right = self.pair(status="blocked")
        with self.assertRaises(ValueError):
            self.tool.compare(left, right)

    def test_missing_case_fails(self):
        left, right = self.pair()
        self.edit(right, lambda data: data["cases"].append({
            **data["cases"][0], "id": "additional"
        }))
        self.assertEqual(self.tool.compare(left, right)["result"], "fail")

    def test_empty_or_duplicate_cases_rejected(self):
        for mutate in [
            lambda data: data.update(cases=[]),
            lambda data: data["cases"].append(data["cases"][0]),
        ]:
            left, right = self.pair()
            self.edit(right, mutate)
            with self.assertRaises(ValueError):
                self.tool.compare(left, right)

    def test_invalid_types_and_schema_rejected(self):
        for changes in [
            {"exit_code": True}, {"checks": {}}, {"checks": {"ok": "true"}},
            {"input_sha256": "fake"}, {"status": "passed"}, {"artifacts": {}},
        ]:
            with self.subTest(changes=changes):
                left, right = self.pair(**changes)
                with self.assertRaises(ValueError):
                    self.tool.compare(left, right)
        left, right = self.pair()
        self.edit(right, lambda data: data.update(schema_version=True))
        with self.assertRaises(ValueError):
            self.tool.compare(left, right)

    def test_duplicate_artifact_or_bad_mode_rejected(self):
        for change in [
            lambda case: case["artifacts"].append(case["artifacts"][0]),
            lambda case: case["artifacts"][0].update(mode="automatic"),
        ]:
            left, right = self.pair()
            self.edit(right, lambda data: change(data["cases"][0]))
            with self.assertRaises(ValueError):
                self.tool.compare(left, right)

    def test_artifact_set_difference_fails(self):
        left, right = self.pair(artifacts=[])
        self.assertEqual(self.tool.compare(left, right)["result"], "fail")

    def test_renamed_physical_file_can_use_same_logical_id(self):
        left, right = self.pair()
        self.write("target/renamed.json", '{"total":3}')
        self.edit(right, lambda data: data["cases"][0]["artifacts"][0].update(path="renamed.json"))
        self.assertEqual(self.tool.compare(left, right)["result"], "pass")

    def test_missing_artifact_rejected(self):
        left, right = self.pair()
        (right.parent / "output" / "result.json").unlink()
        with self.assertRaises(ValueError):
            self.tool.compare(left, right)

    def test_path_escape_absolute_and_backslash_rejected(self):
        for path in [
            "../outside.json", "..\\outside.json", "/absolute.json",
            "C:\\secret.json", "output/result.json:stream",
        ]:
            with self.subTest(path=path):
                left, right = self.pair()
                self.edit(right, lambda data: data["cases"][0]["artifacts"][0].update(path=path))
                with self.assertRaises(ValueError):
                    self.tool.compare(left, right)

    def test_symlink_artifact_rejected(self):
        left, right = self.pair()
        outside = self.write("outside.json", '{"total":3}')
        link = right.parent / "link.json"
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("OS does not allow symlink creation")
        self.edit(right, lambda data: data["cases"][0]["artifacts"][0].update(path="link.json"))
        with self.assertRaises(ValueError):
            self.tool.compare(left, right)

    def test_directory_link_artifact_rejected(self):
        left, right = self.pair()
        outside = self.write("outside/result.json", '{"total":3}').parent
        self.directory_link(right.parent / "linked", outside)
        self.edit(right, lambda data: data["cases"][0]["artifacts"][0].update(path="linked/result.json"))
        with self.assertRaises(ValueError):
            self.tool.compare(left, right)

    def test_linked_manifest_parent_rejected(self):
        left, right = self.pair()
        link = self.root / "linked"
        self.directory_link(link, right.parent)
        with self.assertRaises(ValueError):
            self.tool.compare(left, link / "run.json")

    def test_malformed_manifest_rejected(self):
        left, right = self.pair()
        right.write_text('{"schema_version":1,"schema_version":1,"cases":[]}', encoding="utf-8")
        with self.assertRaises(ValueError):
            self.tool.compare(left, right)

    def test_mode_difference_fails(self):
        left, right = self.pair(mode="text")
        self.assertEqual(self.tool.compare(left, right)["result"], "fail")

    def test_cli_exit_codes_no_content_leak(self):
        left, right = self.pair()
        self.assertEqual(self.cli("compare_runs", left, right).returncode, 0)
        self.write("target/output/result.json", '{"total":"private-payload"}')
        different = self.cli("compare_runs", left, right)
        self.assertEqual(different.returncode, 1)
        self.assertNotIn("private-payload", different.stdout)
        self.write("target/output/result.json", "{private-payload")
        invalid = self.cli("compare_runs", left, right)
        self.assertEqual(invalid.returncode, 2)
        self.assertNotIn("private-payload", invalid.stdout + invalid.stderr)


class BaselineTests(WorkspaceTest):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool("prepare_baseline")
        cls.inspector = load_tool("inspect_skill")

    def prepare(self, source, destination):
        settings = self.inspector.load_settings(ROOT / "config/settings.json")
        return self.tool.prepare(source, destination, settings)

    def source(self):
        self.write("source/SKILL.md", "# Example\n")
        return self.root / "source"

    def test_snapshot_preserves_files_and_writes_manifest(self):
        source = self.source()
        self.write("source/assets/binary.dat", b"\x00\xff\x01")
        (source / "config").mkdir()
        result = self.prepare(source, self.root / "baseline")
        self.assertTrue(result["complete"])
        self.assertEqual(
            (source / "assets/binary.dat").read_bytes(),
            (self.root / "baseline/source/assets/binary.dat").read_bytes(),
        )
        manifest = json.loads((self.root / "baseline/snapshot.json").read_text())
        self.assertEqual(manifest, result)
        self.assertTrue((self.root / "baseline/source/config").is_dir())

    def test_execution_writes_and_import_caches_stay_in_copy(self):
        source = self.source()
        self.write("source/helper.py", "VALUE = 42\n")
        self.write(
            "source/run.py",
            "import helper\nfrom pathlib import Path\n"
            "Path(__file__).with_name('generated.txt').write_text(str(helper.VALUE))\n",
        )
        before = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*") if p.is_file()}
        self.prepare(source, self.root / "baseline")
        env = dict(os.environ)
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        proc = subprocess.run(
            [sys.executable, str(self.root / "baseline/source/run.py")],
            cwd=self.root, env=env, capture_output=True, timeout=15,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((self.root / "baseline/source/generated.txt").read_text(), "42")
        self.assertTrue((self.root / "baseline/source/__pycache__").is_dir())
        after = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_existing_destination_not_overwritten(self):
        source = self.source()
        sentinel = self.write("baseline/sentinel.txt", "keep")
        with self.assertRaises(ValueError):
            self.prepare(source, sentinel.parent)
        self.assertEqual(sentinel.read_text(), "keep")

    def test_source_destination_overlap_rejected(self):
        source = self.source()
        for target in [source, source / "baseline", source.parent]:
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    self.prepare(source, target)

    def test_sensitive_files_and_exclusions_not_copied(self):
        source = self.source()
        self.write("source/.env", "SECRET=private-secret-123456")
        self.write("source/__pycache__/fixture.pyc", b"generated")
        result = self.prepare(source, self.root / "baseline")
        self.assertFalse(result["complete"])
        self.assertEqual(len(result["excluded"]), 2)
        self.assertFalse((self.root / "baseline/source/.env").exists())
        self.assertNotIn("private-secret-123456", json.dumps(result))

    def test_directory_link_rejected_before_creating_copy(self):
        source = self.source()
        external = self.write("outside/file.txt", "outside").parent
        self.directory_link(source / "linked", external)
        with self.assertRaises(ValueError):
            self.prepare(source, self.root / "baseline")
        self.assertFalse((self.root / "baseline").exists())

    def test_changed_source_during_copy_rejected(self):
        source = self.source()
        original = self.tool.shutil.copy2

        def changing(src, dst, **kwargs):
            result = original(src, dst, **kwargs)
            Path(src).write_text("changed during copy", encoding="utf-8")
            return result

        with mock.patch.object(self.tool.shutil, "copy2", changing):
            with self.assertRaises(ValueError):
                self.prepare(source, self.root / "baseline")
        self.assertFalse((self.root / "baseline/snapshot.json").exists())

    def test_cli_works_outside_skill_directory(self):
        source = self.source()
        result = self.cli("prepare_baseline", source, self.root / "baseline")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["complete"])
        again = self.cli("prepare_baseline", source, self.root / "baseline")
        self.assertEqual(again.returncode, 2)


class ExecutionIntegrationTests(WorkspaceTest):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool("compare_runs")

    def test_real_programs_equivalent_and_regression_detected(self):
        source_code = (
            "import csv,json,sys\n"
            "with open(sys.argv[1],newline='',encoding='utf-8') as f:\n"
            "    rows=list(csv.DictReader(f))\n"
            "result={'count':len(rows),'total':sum(int(r['amount']) for r in rows)}\n"
            "with open(sys.argv[2],'w',encoding='utf-8') as f: json.dump(result,f)\n"
        )
        target_code = (
            "import csv,json,sys\n"
            "from pathlib import Path\n"
            "with Path(sys.argv[1]).open(newline='',encoding='utf-8') as handle:\n"
            "    values=[int(row['amount']) for row in csv.DictReader(handle)]\n"
            "Path(sys.argv[2]).write_text(json.dumps({'total':sum(values),'count':len(values)},indent=2),encoding='utf-8')\n"
        )
        source = self.write("programs/source.py", source_code)
        target = self.write("programs/target.py", target_code)
        cases = {
            "normal": ("amount\n1\n2\n", {"count": 2, "total": 3}, 0),
            "empty": ("amount\n", {"count": 0, "total": 0}, 0),
            "negative": ("amount\n-2\n5\n", {"count": 2, "total": 3}, 0),
            "invalid": ("amount\nno-number\n", None, 1),
        }
        records = {}
        for side, program in [("baseline", source), ("target", target)]:
            run_cases = []
            for case_id, (data, expected, expected_exit) in cases.items():
                input_path = self.write(f"input/{case_id}.csv", data)
                output = self.root / side / case_id / "summary.json"
                output.parent.mkdir(parents=True, exist_ok=True)
                proc = subprocess.run(
                    [sys.executable, str(program), str(input_path), str(output)],
                    capture_output=True, timeout=15,
                )
                checks = {"expected_exit": proc.returncode == expected_exit}
                artifacts = []
                if expected is not None:
                    actual = json.loads(output.read_text(encoding="utf-8"))
                    checks["expected_result"] = actual == expected
                    artifacts.append({"id": "summary", "path": f"{case_id}/summary.json", "mode": "json"})
                else:
                    checks["no_output"] = not output.exists()
                run_cases.append({
                    "id": case_id, "status": "executed",
                    "input_sha256": hashlib.sha256(data.encode()).hexdigest(),
                    "exit_code": proc.returncode, "checks": checks, "artifacts": artifacts,
                })
            records[side] = self.write(f"{side}/run.json", json.dumps({"schema_version": 1, "cases": run_cases}))
        self.assertEqual(self.tool.compare(records["baseline"], records["target"])["result"], "pass")
        target.write_text(target_code.replace("sum(values)", "sum(values)+1"), encoding="utf-8")
        bad_output = self.root / "target/normal/summary.json"
        proc = subprocess.run(
            [sys.executable, str(target), str(self.root / "input/normal.csv"), str(bad_output)],
            capture_output=True, timeout=15,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(self.tool.compare(records["baseline"], records["target"])["result"], "fail")

    def test_complete_skill_resource_relocation_and_config_used(self):
        source = self.root / "source"
        target = self.root / "target skill"
        self.write("source/SKILL.md", "---\nname: fixture-source\ndescription: Summarize numbers.\n---\nUse helpers/run.py; output total and label.\n")
        self.write("source/README.md", "# Summarize numbers\n")
        self.write("source/LICENSE", "Fixture permission: retain this notice.\n")
        source_program = (
            "import json,sys\nfrom pathlib import Path\n"
            "root=Path(__file__).resolve().parents[1]\n"
            "config=json.loads((root/'settings.json').read_text(encoding='utf-8'))\n"
            "label=(root/'templates/label.txt').read_text(encoding='utf-8').strip()\n"
            "values=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))\n"
            "result={'total':sum(values)*config['multiplier'],'label':label}\n"
            "Path(sys.argv[2]).write_text(json.dumps(result),encoding='utf-8')\n"
        )
        self.write("source/helpers/run.py", source_program)
        self.write("source/settings.json", '{"multiplier":2}')
        self.write("source/templates/label.txt", "Summary")
        source_before = {
            p.relative_to(source).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in source.rglob("*") if p.is_file()
        }
        self.write("target skill/SKILL.md", "---\nname: fixture-summary\ndescription: Summarize numbers.\n---\nUse scripts/run.py; output total and label.\n")
        self.write("target skill/README.md", "# Number Summary\nRun with an input JSON array and output path.\n")
        self.write("target skill/LICENSE", (source / "LICENSE").read_text(encoding="utf-8"))
        self.write("target skill/agents/openai.yaml", 'interface:\n  display_name: "Summary"\n  default_prompt: "Use $fixture-summary."\n')
        self.write(
            "target skill/scripts/run.py",
            source_program.replace("root/'settings.json'", "root/'config/settings.json'")
            .replace("root/'templates/label.txt'", "root/'assets/label.txt'"),
        )
        self.write("target skill/config/settings.json", '{"multiplier":2}')
        self.write("target skill/assets/label.txt", "Summary")
        input_path = self.write("input.json", "[1,2,3]")
        for side, entry in [
            ("source", source / "helpers/run.py"),
            ("target", target / "scripts/run.py"),
        ]:
            output = self.root / f"{side}-result.json"
            proc = subprocess.run(
                [sys.executable, str(entry), str(input_path), str(output)],
                cwd=self.root, capture_output=True, timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(output.read_text()), {"total": 12, "label": "Summary"})
        self.assertEqual(
            (source / "LICENSE").read_bytes(), (target / "LICENSE").read_bytes()
        )
        self.write("target skill/config/settings.json", '{"multiplier":3}')
        output = self.root / "changed-config.json"
        proc = subprocess.run(
            [sys.executable, str(target / "scripts/run.py"), str(input_path), str(output)],
            cwd=self.root, capture_output=True, timeout=15,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(output.read_text())["total"], 18)
        source_after = {
            p.relative_to(source).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in source.rglob("*") if p.is_file()
        }
        self.assertEqual(source_before, source_after)

    def test_real_missing_dependency_recorded_as_blocked(self):
        proc = subprocess.run(
            [sys.executable, "-I", "-S", "-c", "import skill_reforge_nonexistent_fixture_dependency"],
            capture_output=True, timeout=15,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"ModuleNotFoundError", proc.stderr)
        run = {"schema_version": 1, "cases": [{
            "id": "external_service", "status": "blocked", "reason": "Missing dependency"
        }]}
        left = self.write("baseline/run.json", json.dumps(run))
        right = self.write("target/run.json", json.dumps(run))
        self.assertEqual(self.tool.compare(left, right)["result"], "blocked")


if __name__ == "__main__":
    unittest.main()

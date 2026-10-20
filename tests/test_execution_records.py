"""Planned coverage and truthful command/function/model execution records."""

import hashlib
import json
import subprocess
import sys

from test_tools import WorkspaceTest, load_tool


class PlannedExecutionTests(WorkspaceTest):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool("compare_runs")

    def plan(self, **changes):
        case = {
            "id": "normal", "execution_kind": "function",
            "input_sha256": hashlib.sha256(b"same-input").hexdigest(),
            "required": True,
        }
        case.update(changes)
        return self.write("plan.json", json.dumps({"schema_version": 1, "cases": [case]}))

    def record(self, side, **changes):
        case = {
            "id": "normal", "execution_kind": "function", "status": "executed",
            "input_sha256": hashlib.sha256(b"same-input").hexdigest(),
            "checks": {"expected_result": sum([1, 2]) == 3}, "artifacts": [],
        }
        case.update(changes)
        return self.write(f"{side}/run.json", json.dumps({"schema_version": 2, "cases": [case]}))

    def pair(self, **changes):
        return self.record("baseline", **changes), self.record("target", **changes)

    def compare(self, left, right, plan=None):
        return self.tool.compare(left, right, plan or self.plan())

    def test_function_execution_has_no_process_exit_code(self):
        left, right = self.pair()
        self.assertEqual(self.compare(left, right)["result"], "pass")
        self.assertEqual(self.compare(left, right)["scope"], "planned_cases")

    def test_model_record_is_compared_without_a_process_exit_code(self):
        left, right = self.pair(execution_kind="model")
        plan = self.plan(execution_kind="model")
        self.assertEqual(self.compare(left, right, plan)["result"], "pass")

    def test_function_and_model_reject_invented_exit_codes(self):
        for kind in ("function", "model"):
            with self.subTest(kind=kind):
                left, right = self.pair(execution_kind=kind, exit_code=0)
                with self.assertRaises(ValueError):
                    self.compare(left, right, self.plan(execution_kind=kind))

    def test_real_command_records_actual_nonzero_exit_code(self):
        proc = subprocess.run(
            [sys.executable, "-I", "-S", "-c", "raise SystemExit(3)"],
            capture_output=True, timeout=15,
        )
        self.assertEqual(proc.returncode, 3)
        left, right = self.pair(execution_kind="command", exit_code=proc.returncode)
        self.assertEqual(
            self.compare(left, right, self.plan(execution_kind="command"))["result"], "pass"
        )

    def test_command_requires_integer_exit_code(self):
        for value in (None, True, "0"):
            with self.subTest(value=value):
                left, right = self.pair(execution_kind="command", exit_code=value)
                with self.assertRaises(ValueError):
                    self.compare(left, right, self.plan(execution_kind="command"))

    def test_v2_requires_predeclared_plan(self):
        left, right = self.pair()
        with self.assertRaises(ValueError):
            self.tool.compare(left, right)
        result = self.cli("compare_runs", left, right)
        self.assertEqual(result.returncode, 2)

    def test_case_omitted_from_both_runs_fails_against_plan(self):
        left, right = self.pair()
        for path in (left, right):
            path.write_text('{"schema_version":2,"cases":[]}', encoding="utf-8")
        result = self.compare(left, right)
        self.assertEqual(result["result"], "fail")
        self.assertEqual(result["issues"][0]["category"], "missing_case")

    def test_extra_case_not_in_plan_fails(self):
        left, right = self.pair(id="unplanned")
        self.assertEqual(self.compare(left, right)["result"], "fail")
        self.assertIn("unplanned_case", json.dumps(self.compare(left, right)))

    def test_plan_binds_kind_and_input_even_if_both_runs_agree(self):
        for changes in ({"input_sha256": "b" * 64}, {"execution_kind": "model"}):
            with self.subTest(changes=changes):
                left, right = self.pair(**changes)
                result = self.compare(left, right)
                self.assertEqual(result["result"], "fail")
                self.assertIn("plan_", json.dumps(result))

    def test_failed_function_remains_a_failed_record_without_exit_code(self):
        left, right = self.pair()
        case = json.loads(right.read_text(encoding="utf-8"))["cases"][0]
        case.update(status="failed", reason="assertion_failed")
        case.pop("checks")
        case.pop("artifacts")
        right.write_text(json.dumps({"schema_version": 2, "cases": [case]}), encoding="utf-8")
        self.assertEqual(self.compare(left, right)["result"], "fail")

    def test_nonexecuted_statuses_never_pass_required_case(self):
        for status in ("blocked", "not-run", "not-applicable"):
            with self.subTest(status=status):
                case = {
                    "id": "normal", "execution_kind": "function", "status": status,
                    "input_sha256": hashlib.sha256(b"same-input").hexdigest(),
                    "reason": "not_available",
                }
                paths = [
                    self.write(f"{side}/run.json", json.dumps({"schema_version": 2, "cases": [case]}))
                    for side in ("baseline", "target")
                ]
                self.assertNotEqual(self.compare(*paths)["result"], "pass")

    def test_only_optional_case_may_be_not_applicable_but_is_not_a_pass(self):
        case = {
            "id": "normal", "execution_kind": "function", "status": "not-applicable",
            "input_sha256": hashlib.sha256(b"same-input").hexdigest(),
            "reason": "capability_absent",
        }
        paths = [
            self.write(f"{side}/run.json", json.dumps({"schema_version": 2, "cases": [case]}))
            for side in ("baseline", "target")
        ]
        result = self.compare(*paths, plan=self.plan(required=False))
        self.assertEqual(result["result"], "not-applicable")

    def test_invalid_plan_rejected(self):
        left, right = self.pair()
        for changes in (
            {"required": "false"}, {"execution_kind": "other"},
            {"execution_kind": []}, {"input_sha256": "bad"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    self.compare(left, right, self.plan(**changes))
        plan = self.plan()
        data = json.loads(plan.read_text(encoding="utf-8"))
        data["cases"].append(data["cases"][0])
        plan.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.compare(left, right, plan)

    def test_invalid_v2_status_and_duplicate_records_rejected(self):
        for changes in ({"status": []}, {"status": "passed"}, {"execution_kind": []}):
            with self.subTest(changes=changes):
                left, right = self.pair(**changes)
                with self.assertRaises(ValueError):
                    self.compare(left, right)
        left, right = self.pair()
        data = json.loads(right.read_text(encoding="utf-8"))
        data["cases"].append(data["cases"][0])
        right.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.compare(left, right)

    def test_failed_assertions_and_changed_real_artifacts_do_not_pass(self):
        for false_check in (False, True):
            with self.subTest(false_check=false_check):
                artifacts = [{"id": "sum", "path": "result.json", "mode": "json"}]
                left, right = self.pair(
                    checks={"expected_result": not false_check}, artifacts=artifacts
                )
                self.write("baseline/result.json", json.dumps({"sum": sum([1, 2])}))
                self.write("target/result.json", json.dumps({"sum": sum([1, 2]) + 1}))
                self.assertEqual(self.compare(left, right)["result"], "fail")
                self.write("target/result.json", '{"sum":3}')
                self.assertEqual(
                    self.compare(left, right)["result"], "fail" if false_check else "pass"
                )

    def test_optional_not_applicable_can_coexist_with_a_real_pass(self):
        plan = self.plan(required=False)
        data = json.loads(plan.read_text(encoding="utf-8"))
        data["cases"].append({**data["cases"][0], "id": "executed", "required": True})
        plan.write_text(json.dumps(data), encoding="utf-8")
        paths = self.pair()
        for path in paths:
            data = json.loads(path.read_text(encoding="utf-8"))
            executed = {**data["cases"][0], "id": "executed"}
            optional = {
                key: value for key, value in data["cases"][0].items()
                if key not in ("checks", "artifacts")
            }
            optional.update(status="not-applicable", reason="capability_absent")
            data["cases"] = [executed, optional]
            path.write_text(json.dumps(data), encoding="utf-8")
        result = self.compare(*paths, plan=plan)
        self.assertEqual(result["result"], "pass")
        self.assertIn({"id": "normal", "result": "not-applicable"}, result["cases"])

    def test_v1_can_use_plan_but_mixed_versions_are_rejected(self):
        left, right = self.pair(execution_kind="command", exit_code=0)
        data = json.loads(left.read_text(encoding="utf-8"))
        data["schema_version"] = 1
        left.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.compare(left, right, self.plan(execution_kind="command"))
        right.write_text(json.dumps(data), encoding="utf-8")
        self.assertEqual(
            self.compare(left, right, self.plan(execution_kind="command"))["scope"], "planned_cases"
        )

    def test_legacy_scope_is_explicit(self):
        left, right = self.pair(execution_kind="command", exit_code=0)
        for path in (left, right):
            data = json.loads(path.read_text(encoding="utf-8"))
            data["schema_version"] = 1
            path.write_text(json.dumps(data), encoding="utf-8")
        result = self.tool.compare(left, right)
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["scope"], "recorded_cases_only")

    def test_cli_accepts_plan_from_another_directory(self):
        left, right = self.pair()
        result = self.cli("compare_runs", left, right, "--plan", self.plan())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["scope"], "planned_cases")

"""Actionable baseline errors without paths, secret values or raw exceptions."""

import contextlib
import io
import json
from unittest import mock

from test_tools import WorkspaceTest, load_tool


class BaselineDiagnosticTests(WorkspaceTest):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool("prepare_baseline")

    def source(self):
        return self.write("source/SKILL.md", "# Example\n").parent

    def assert_error(self, args, reason, partial=False):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = self.tool.main(list(map(str, args)))
        data = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(data["error"], "snapshot_failed")
        self.assertEqual(data["reason"], reason)
        self.assertEqual(data["partial_copy"], partial)
        self.assertNotIn(str(self.root), output.getvalue())
        return data

    def test_missing_and_invalid_configuration(self):
        source = self.source()
        for content in (None, "{private-content", '{"exclude_dirs":[]}'):
            with self.subTest(content=content):
                config = self.root / "settings.json"
                if content is not None:
                    config.write_text(content, encoding="utf-8")
                self.assert_error(
                    [source, self.root / "baseline", "--config", config], "invalid_config"
                )
                self.assertFalse((self.root / "baseline").exists())

    def test_existing_destination_is_identified_and_untouched(self):
        sentinel = self.write("baseline/sentinel.txt", "keep")
        self.assert_error([self.source(), sentinel.parent], "destination_exists")
        self.assertEqual(sentinel.read_text(), "keep")

    def test_missing_parent_is_distinct_from_existing_destination(self):
        self.assert_error(
            [self.source(), self.root / "missing" / "baseline"], "invalid_destination_parent"
        )

    def test_missing_source_is_identified(self):
        self.assert_error([self.root / "missing", self.root / "baseline"], "invalid_source")

    def test_overlap_is_identified_before_creating_copy(self):
        source = self.source()
        self.assert_error([source, source / "baseline"], "overlapping_paths")
        self.assertFalse((source / "baseline").exists())

    def test_permission_failure_reports_partial_copy_without_raw_error(self):
        source = self.source()
        with mock.patch.object(
            self.tool.shutil, "copy2", side_effect=PermissionError("private-secret-path")
        ):
            self.assert_error([source, self.root / "baseline"], "permission_denied", partial=True)
        self.assertFalse((self.root / "baseline/snapshot.json").exists())

    def test_changed_source_reports_partial_copy(self):
        source = self.source()
        original = self.tool.shutil.copy2

        def changing(src, dst, **kwargs):
            result = original(src, dst, **kwargs)
            src.write_text("changed", encoding="utf-8")
            return result

        with mock.patch.object(self.tool.shutil, "copy2", changing):
            self.assert_error([source, self.root / "baseline"], "source_changed", partial=True)
        self.assertFalse((self.root / "baseline/snapshot.json").exists())

    def test_linked_source_has_specific_diagnostic(self):
        outside = self.write("outside/SKILL.md", "# Example").parent
        link = self.root / "source"
        self.directory_link(link, outside)
        self.assert_error([link, self.root / "baseline"], "linked_source")

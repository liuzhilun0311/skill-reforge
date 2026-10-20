"""Distribution checks without optional dependencies or generated files."""

import ast
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DistributionTests(unittest.TestCase):
    def test_required_files_and_utf8(self):
        expected = [
            "README.md", "SKILL.md", "agents/openai.yaml", "config/settings.json",
            "scripts/inspect_skill.py", "scripts/compare_runs.py",
            "scripts/prepare_baseline.py",
            "references/analysis.md", "references/restructuring.md",
            "references/validation.md", "assets/report-template.md",
            "references/release.md", "references/behavioral-evaluation.md",
        ]
        for name in expected:
            with self.subTest(name=name):
                path = ROOT / name
                self.assertTrue(path.is_file())
                self.assertTrue(path.read_text(encoding="utf-8").strip())

    def test_local_markdown_links_resolve_within_package(self):
        count = 0
        for path in ROOT.rglob("*.md"):
            for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
                target = match.group(1)
                if target.startswith(("https://", "http://", "#")):
                    continue
                target_path = (path.parent / target.split("#", 1)[0]).resolve()
                self.assertTrue(target_path.is_relative_to(ROOT), (path, target))
                self.assertTrue(target_path.exists(), (path, target))
                count += 1
        self.assertGreaterEqual(count, 5)

    def test_scripts_are_syntactically_valid(self):
        for path in (ROOT / "scripts").glob("*.py"):
            with self.subTest(name=path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_configuration_shape_and_types(self):
        settings = json.loads((ROOT / "config/settings.json").read_text(encoding="utf-8"))
        self.assertGreater(settings["max_text_bytes"], 0)
        self.assertTrue(all(isinstance(item, str) for item in settings["exclude_dirs"]))
        self.assertEqual(set(settings), {"exclude_dirs", "max_text_bytes", "sensitive_names"})


if __name__ == "__main__":
    unittest.main()

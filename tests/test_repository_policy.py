import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
USES_PATTERN = re.compile(r"uses:\s*[^@\s]+@([^\s#]+)")
FULL_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class RepositoryPolicyTests(unittest.TestCase):
    def workflow_text(self) -> str:
        return "\n".join(path.read_text(encoding="utf-8") for path in sorted(WORKFLOWS.glob("*.yml")))

    def test_actions_are_pinned_to_full_shas(self) -> None:
        text = self.workflow_text()
        references = USES_PATTERN.findall(text)
        self.assertGreater(len(references), 0)
        self.assertTrue(all(FULL_SHA_PATTERN.fullmatch(reference) for reference in references))

    def test_checkout_disables_persisted_credentials(self) -> None:
        for path in WORKFLOWS.glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            if "actions/checkout" in text:
                self.assertIn("persist-credentials: false", text)

    def test_workflows_have_manual_dispatch(self) -> None:
        for name in ("bandit.yml", "codeql.yml"):
            self.assertIn("workflow_dispatch:", (WORKFLOWS / name).read_text(encoding="utf-8"))

    def test_codeql_has_weekly_schedule(self) -> None:
        text = (WORKFLOWS / "codeql.yml").read_text(encoding="utf-8")
        self.assertIn("schedule:", text)
        self.assertIn("cron:", text)

    def test_top_level_permissions_are_read_only(self) -> None:
        for path in WORKFLOWS.glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            self.assertIn("permissions:\n  contents: read", text)


if __name__ == "__main__":
    unittest.main()

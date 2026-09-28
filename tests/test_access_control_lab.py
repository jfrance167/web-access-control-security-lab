import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from access_control_lab import (
    AccessRequest,
    ScenarioError,
    build_lab_state,
    load_scenarios,
    main,
    render_markdown,
    run_lab,
    secure_authorize,
    vulnerable_authorize,
)


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "samples" / "access-control-scenarios.json"


class AccessControlLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = build_lab_state()

    def request(self, **overrides: object) -> AccessRequest:
        values: dict[str, object] = {
            "scenario": "test",
            "session_id": "sess-alice",
            "endpoint": "/documents",
            "action": "read",
            "resource_id": "doc-alice",
        }
        values.update(overrides)
        return AccessRequest(**values)  # type: ignore[arg-type]

    def test_fixture_contains_eleven_scenarios(self) -> None:
        self.assertEqual(len(load_scenarios(SCENARIOS)), 11)

    def test_complete_experiment_passes(self) -> None:
        results = run_lab(load_scenarios(SCENARIOS), self.state)
        self.assertTrue(all(result.passed for result in results))

    def test_experiment_demonstrates_six_broken_exposures(self) -> None:
        results = run_lab(load_scenarios(SCENARIOS), self.state)
        exposures = [result for result in results if result.vulnerable_allowed and not result.expected_secure]
        self.assertEqual(len(exposures), 6)

    def test_vulnerable_policy_allows_horizontal_idor(self) -> None:
        request = self.request(resource_id="doc-bob")
        self.assertTrue(vulnerable_authorize(request, self.state).allowed)

    def test_secure_policy_denies_horizontal_idor(self) -> None:
        request = self.request(resource_id="doc-bob")
        self.assertFalse(secure_authorize(request, self.state).allowed)

    def test_secure_policy_allows_owner(self) -> None:
        self.assertTrue(secure_authorize(self.request(), self.state).allowed)

    def test_secure_policy_allows_tenant_shared_read(self) -> None:
        request = self.request(resource_id="doc-shared")
        self.assertTrue(secure_authorize(request, self.state).allowed)

    def test_secure_policy_denies_tenant_shared_update(self) -> None:
        request = self.request(resource_id="doc-shared", action="update")
        self.assertFalse(secure_authorize(request, self.state).allowed)

    def test_vulnerable_policy_trusts_claimed_admin_role(self) -> None:
        request = self.request(endpoint="/admin/export", action="export", resource_id=None, claimed_role="admin")
        self.assertTrue(vulnerable_authorize(request, self.state).allowed)

    def test_secure_policy_rejects_claimed_admin_role(self) -> None:
        request = self.request(endpoint="/admin/export", action="export", resource_id=None, claimed_role="admin")
        self.assertFalse(secure_authorize(request, self.state).allowed)

    def test_secure_policy_allows_real_admin_export(self) -> None:
        request = self.request(session_id="sess-admin", endpoint="/admin/export", action="export", resource_id=None)
        self.assertTrue(secure_authorize(request, self.state).allowed)

    def test_secure_policy_denies_cross_tenant_access(self) -> None:
        request = self.request(resource_id="doc-carol")
        decision = secure_authorize(request, self.state)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.control, "tenant-boundary")

    def test_secure_policy_denies_disabled_user(self) -> None:
        request = self.request(session_id="sess-disabled", endpoint="/admin/export", action="export", resource_id=None)
        self.assertFalse(secure_authorize(request, self.state).allowed)

    def test_secure_policy_denies_anonymous_user(self) -> None:
        self.assertFalse(secure_authorize(self.request(session_id=None), self.state).allowed)

    def test_secure_policy_denies_unknown_endpoint(self) -> None:
        self.assertFalse(secure_authorize(self.request(endpoint="/debug"), self.state).allowed)

    def test_secure_policy_denies_unknown_action(self) -> None:
        self.assertFalse(secure_authorize(self.request(action="impersonate"), self.state).allowed)

    def test_secure_policy_rejects_conflicting_claimed_identity(self) -> None:
        request = self.request(claimed_user_id="bob")
        self.assertFalse(secure_authorize(request, self.state).allowed)

    def test_secure_policy_denies_missing_resource(self) -> None:
        self.assertFalse(secure_authorize(self.request(resource_id="missing"), self.state).allowed)

    def test_load_rejects_non_array(self) -> None:
        path = ROOT / "reports" / ".test-non-array.json"
        self.addCleanup(path.unlink, missing_ok=True)
        path.write_text("{}", encoding="utf-8")
        with self.assertRaises(ScenarioError):
            load_scenarios(path)

    def test_load_rejects_non_boolean_expectation(self) -> None:
        path = ROOT / "reports" / ".test-invalid-expectation.json"
        self.addCleanup(path.unlink, missing_ok=True)
        path.write_text(json.dumps([{"scenario": "x", "category": "x", "endpoint": "/x", "action": "read", "expected_secure": "no"}]), encoding="utf-8")
        with self.assertRaises(ScenarioError):
            load_scenarios(path)

    def test_report_escapes_untrusted_cells(self) -> None:
        scenarios = load_scenarios(SCENARIOS)
        results = list(run_lab(scenarios, self.state))
        altered = results[0].__class__(**{**results[0].__dict__, "scenario": "cell|break\nline"})
        report = render_markdown([altered], "fixture.json")
        self.assertIn("cell\\|break line", report)

    def test_cli_writes_report(self) -> None:
        output = ROOT / "reports" / ".test-cli-report.md"
        self.addCleanup(output.unlink, missing_ok=True)
        with redirect_stdout(io.StringIO()):
            code = main([str(SCENARIOS), "--output", str(output), "--fail-on-regression"])
        self.assertEqual(code, 0)
        self.assertIn("Secure-policy expectations passed: **11/11**", output.read_text(encoding="utf-8"))

    def test_cli_json_output(self) -> None:
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = main([str(SCENARIOS), "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(stream.getvalue())), 11)


if __name__ == "__main__":
    unittest.main()

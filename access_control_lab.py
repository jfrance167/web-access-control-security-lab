#!/usr/bin/env python3
"""Model vulnerable and secure authorization decisions for a safe local lab."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence


ALLOWED_ACTIONS = {"read", "update", "delete", "export", "list_users"}
ROLE_PERMISSIONS = {
    "viewer": frozenset({"read"}),
    "analyst": frozenset({"read", "update"}),
    "admin": frozenset(ALLOWED_ACTIONS),
}


class ScenarioError(ValueError):
    """Raised when a scenario file fails validation."""


@dataclass(frozen=True)
class User:
    user_id: str
    tenant_id: str
    role: str
    enabled: bool = True


@dataclass(frozen=True)
class Resource:
    resource_id: str
    tenant_id: str
    owner_id: str
    visibility: str = "private"


@dataclass(frozen=True)
class AccessRequest:
    scenario: str
    session_id: str | None
    endpoint: str
    action: str
    resource_id: str | None = None
    claimed_user_id: str | None = None
    claimed_role: str | None = None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    control: str


@dataclass(frozen=True)
class ScenarioResult:
    scenario: str
    category: str
    expected_secure: bool
    vulnerable_allowed: bool
    vulnerable_reason: str
    secure_allowed: bool
    secure_reason: str
    passed: bool


@dataclass(frozen=True)
class LabState:
    users: Mapping[str, User]
    sessions: Mapping[str, str]
    resources: Mapping[str, Resource]


def build_lab_state() -> LabState:
    """Return deterministic fictional users, sessions, and documents."""
    users = {
        "alice": User("alice", "acme", "analyst"),
        "bob": User("bob", "acme", "viewer"),
        "carol": User("carol", "globex", "analyst"),
        "admin-acme": User("admin-acme", "acme", "admin"),
        "disabled": User("disabled", "acme", "admin", enabled=False),
    }
    sessions = {
        "sess-alice": "alice",
        "sess-bob": "bob",
        "sess-carol": "carol",
        "sess-admin": "admin-acme",
        "sess-disabled": "disabled",
    }
    resources = {
        "doc-alice": Resource("doc-alice", "acme", "alice"),
        "doc-bob": Resource("doc-bob", "acme", "bob"),
        "doc-shared": Resource("doc-shared", "acme", "bob", visibility="tenant"),
        "doc-carol": Resource("doc-carol", "globex", "carol"),
    }
    return LabState(users=users, sessions=sessions, resources=resources)


def _authenticated_user(request: AccessRequest, state: LabState) -> User | None:
    if request.session_id is None:
        return None
    user_id = state.sessions.get(request.session_id)
    return state.users.get(user_id) if user_id else None


def vulnerable_authorize(request: AccessRequest, state: LabState) -> Decision:
    """Demonstrate common broken-access-control logic without a live service.

    This function is intentionally insecure lab material. It trusts client claims
    and does not consistently enforce ownership or tenant boundaries.
    """
    session_user = _authenticated_user(request, state)
    if session_user is None:
        return Decision(False, "No recognized session", "authentication-only")

    client_role = request.claimed_role or session_user.role
    client_user = request.claimed_user_id or session_user.user_id

    if request.endpoint.startswith("/admin/"):
        allowed = client_role == "admin"
        return Decision(allowed, "Client-supplied role checked", "client-role")

    resource = state.resources.get(request.resource_id or "")
    if resource is None:
        return Decision(False, "Resource not found", "existence-check")

    if request.action in {"read", "update"}:
        return Decision(True, "Any authenticated user may access the object", "authentication-only")
    if request.action == "delete":
        allowed = client_role == "admin" or client_user == resource.owner_id
        return Decision(allowed, "Client identity or role accepted", "client-claims")
    return Decision(False, "Action not implemented", "implicit-deny")


def secure_authorize(request: AccessRequest, state: LabState) -> Decision:
    """Enforce server-side identity, RBAC, ownership, tenancy, and default denial."""
    user = _authenticated_user(request, state)
    if user is None:
        return Decision(False, "Authentication required", "server-session")
    if not user.enabled:
        return Decision(False, "Account is disabled", "account-state")

    if request.claimed_user_id not in {None, user.user_id}:
        return Decision(False, "Client identity conflicts with the server session", "identity-binding")
    if request.claimed_role not in {None, user.role}:
        return Decision(False, "Client role conflicts with the server-side role", "server-rbac")
    if request.action not in ALLOWED_ACTIONS:
        return Decision(False, "Unknown action denied by default", "default-deny")

    permissions = ROLE_PERMISSIONS.get(user.role, frozenset())
    if request.action not in permissions:
        return Decision(False, "Role does not grant the requested action", "server-rbac")

    if request.endpoint in {"/admin/export", "/admin/users"}:
        allowed = user.role == "admin" and request.action in {"export", "list_users"}
        reason = "Server-side administrator permission verified" if allowed else "Administrator permission required"
        return Decision(allowed, reason, "server-rbac")

    if request.endpoint != "/documents":
        return Decision(False, "Endpoint is not in the authorization policy", "default-deny")

    resource = state.resources.get(request.resource_id or "")
    if resource is None:
        return Decision(False, "Resource not found", "object-lookup")
    if resource.tenant_id != user.tenant_id:
        return Decision(False, "Cross-tenant access is forbidden", "tenant-boundary")

    if user.role == "admin":
        return Decision(True, "Administrator access is limited to the same tenant", "tenant-rbac")
    if resource.owner_id == user.user_id:
        return Decision(True, "Owner permission verified", "object-ownership")
    if resource.visibility == "tenant" and request.action == "read":
        return Decision(True, "Read access granted to a tenant-shared object", "tenant-sharing")
    return Decision(False, "Object ownership or sharing policy denied access", "object-ownership")


def _require_string(item: Mapping[str, object], field: str, index: int) -> str:
    value = item.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ScenarioError(f"scenario {index}: {field} must be a non-empty string")
    return value


def load_scenarios(path: Path) -> tuple[tuple[str, bool, AccessRequest], ...]:
    """Load and validate scenario definitions from JSON."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScenarioError(f"unable to load {path}: {exc}") from exc
    if not isinstance(raw, list):
        raise ScenarioError("scenario file must contain a JSON array")

    scenarios: list[tuple[str, bool, AccessRequest]] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ScenarioError(f"scenario {index}: entry must be an object")
        action = _require_string(item, "action", index)
        expected = item.get("expected_secure")
        if not isinstance(expected, bool):
            raise ScenarioError(f"scenario {index}: expected_secure must be a boolean")
        optional_fields: dict[str, str | None] = {}
        for field in ("session_id", "resource_id", "claimed_user_id", "claimed_role"):
            value = item.get(field)
            if value is not None and not isinstance(value, str):
                raise ScenarioError(f"scenario {index}: {field} must be a string or null")
            optional_fields[field] = value
        request = AccessRequest(
            scenario=_require_string(item, "scenario", index),
            session_id=optional_fields["session_id"],
            endpoint=_require_string(item, "endpoint", index),
            action=action,
            resource_id=optional_fields["resource_id"],
            claimed_user_id=optional_fields["claimed_user_id"],
            claimed_role=optional_fields["claimed_role"],
        )
        scenarios.append((_require_string(item, "category", index), expected, request))
    return tuple(scenarios)


def run_lab(scenarios: Sequence[tuple[str, bool, AccessRequest]], state: LabState) -> tuple[ScenarioResult, ...]:
    results = []
    for category, expected, request in scenarios:
        vulnerable = vulnerable_authorize(request, state)
        secure = secure_authorize(request, state)
        results.append(
            ScenarioResult(
                scenario=request.scenario,
                category=category,
                expected_secure=expected,
                vulnerable_allowed=vulnerable.allowed,
                vulnerable_reason=vulnerable.reason,
                secure_allowed=secure.allowed,
                secure_reason=secure.reason,
                passed=secure.allowed == expected,
            )
        )
    return tuple(results)


def _escape_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(results: Sequence[ScenarioResult], source: str) -> str:
    passed = sum(result.passed for result in results)
    exposed = sum(result.vulnerable_allowed and not result.expected_secure for result in results)
    lines = [
        "# Access Control Experiment Results",
        "",
        f"- Scenario source: `{source}`",
        f"- Scenarios evaluated: **{len(results)}**",
        f"- Secure-policy expectations passed: **{passed}/{len(results)}**",
        f"- Broken-policy unauthorized exposures: **{exposed}**",
        "",
        "| Scenario | Category | Expected secure | Vulnerable | Secure | Result |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for result in results:
        lines.append(
            "| " + " | ".join(
                _escape_cell(value)
                for value in (
                    result.scenario,
                    result.category,
                    "ALLOW" if result.expected_secure else "DENY",
                    "ALLOW" if result.vulnerable_allowed else "DENY",
                    "ALLOW" if result.secure_allowed else "DENY",
                    "PASS" if result.passed else "FAIL",
                )
            ) + " |"
        )
    lines.extend(
        [
            "",
            "## Secure Design Controls",
            "",
            "1. Bind identity and role to trusted server-side sessions.",
            "2. Check authorization for every endpoint and object operation.",
            "3. Enforce tenant boundaries before ownership or role decisions.",
            "4. Apply least privilege and deny unknown actions by default.",
            "5. Test negative authorization cases as regression requirements.",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenarios", type=Path, help="JSON scenario file")
    parser.add_argument("--output", type=Path, help="write a Markdown results report")
    parser.add_argument("--format", choices=("summary", "json"), default="summary")
    parser.add_argument("--fail-on-regression", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        scenarios = load_scenarios(args.scenarios)
    except ScenarioError as exc:
        print(f"error: {exc}")
        return 2
    results = run_lab(scenarios, build_lab_state())
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(render_markdown(results, args.scenarios.name), encoding="utf-8")
    if args.format == "json":
        print(json.dumps([asdict(result) for result in results], indent=2, sort_keys=True))
    else:
        passed = sum(result.passed for result in results)
        exposures = sum(result.vulnerable_allowed and not result.expected_secure for result in results)
        print(f"scenarios={len(results)} secure_passed={passed} vulnerable_exposures={exposures}")
    return 1 if args.fail_on_regression and not all(result.passed for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())

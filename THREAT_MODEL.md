# Threat Model

## Assets

- Private tenant documents
- Administrative exports and user listings
- Session-to-user identity bindings
- Server-maintained roles and account state

## Trust boundaries

Everything supplied by a client is untrusted, including object identifiers, route paths, claimed user IDs, and claimed roles. Session resolution, account status, tenant membership, roles, and authorization policies belong to the trusted server boundary.

## Threats and controls

| Threat | Security control | Negative test |
|---|---|---|
| IDOR/horizontal escalation | Ownership and sharing checks | Alice requests Bob's private document |
| Vertical privilege escalation | Server-side RBAC | Alice claims the administrator role |
| Forced browsing | Endpoint-level authorization | Bob requests `/admin/users` directly |
| Tenant breakout | Tenant boundary before object access | Acme user requests Globex data |
| Stale privileged session | Account-state validation | Disabled administrator reuses a session |
| Policy gap | Explicit route/action allowlist and default deny | User requests an unknown endpoint/action |

## Residual risk

The model assumes trusted session creation and an accurate data layer. A real deployment must also secure authentication, session cookies, token verification, database filters, service-to-service identity, cache keys, audit logs, and administrative provisioning.

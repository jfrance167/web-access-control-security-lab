# Broken Access Control and Privilege Escalation Lab Report

## Research question

Can a centralized, server-side authorization policy prevent horizontal, vertical, forced-browsing, and cross-tenant access failures while preserving legitimate access?

## Hypothesis

An authentication-only policy that accepts client identity or role claims will expose protected operations. A policy that binds identity to a server-side session and evaluates role, action, tenant, ownership, and resource visibility on every request will block the unauthorized cases.

## Variables

- **Independent variable:** authorization policy (vulnerable or secure).
- **Dependent variable:** allow or deny decision for each request.
- **Controlled variables:** users, sessions, roles, tenants, resources, actions, endpoints, and scenario ordering.

## Method

1. Create fictional users in two tenants with viewer, analyst, and administrator roles.
2. Define three valid requests and eight negative authorization cases.
3. Evaluate every request with the intentionally incomplete policy.
4. Evaluate the same request with the secure reference policy.
5. Compare secure results with the expected decision.
6. Run automated unit, policy, Bandit, and CodeQL checks.

No live website was attacked. The insecure behavior is a local decision model created solely for defensive education.

## Results

The experiment evaluated 11 scenarios. The vulnerable policy allowed six requests that should have been denied:

1. Horizontal access to another user's private document.
2. Horizontal modification of another user's document.
3. Vertical escalation using a client-supplied administrator role.
4. Forced browsing to an administrator endpoint using that role claim.
5. Cross-tenant access to another organization's document.
6. Reuse of an old session belonging to a disabled administrator.

The secure policy matched all 11 expected decisions and preserved all three legitimate operations. See `reports/access-control-results.md` for the generated evidence matrix.

## Analysis

Authentication did not establish authorization. Object identifiers, endpoint paths, and client-provided role values were attacker-controlled inputs in the vulnerable design. The secure design corrected the trust boundary by resolving identity and role from server state, checking permissions for every operation, enforcing tenant separation before object rules, and denying unrecognized behavior.

## Framework mapping

| Observation | Mapping |
|---|---|
| Missing or inconsistent authorization | OWASP A01: Broken Access Control; CWE-862 |
| User-controlled object identifier exposes another user's record | CWE-639 |
| Client-controlled role enables administrative behavior | CWE-284 |
| Cross-tenant object access | OWASP A01; CWE-639 |

## Limitations

This deterministic model isolates authorization logic; it does not reproduce a complete web stack, browser, proxy, database, session cookie, or identity provider. Production testing must also address session fixation, CSRF, token validation, caching, race conditions, logging, and authorization consistency across services.

## Conclusion

The hypothesis was supported. Centralized server-side authorization, tenant isolation, object-level checks, least privilege, and deny-by-default behavior prevented every modeled unauthorized request without blocking the legitimate controls.

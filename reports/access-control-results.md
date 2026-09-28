# Access Control Experiment Results

- Scenario source: `access-control-scenarios.json`
- Scenarios evaluated: **11**
- Secure-policy expectations passed: **11/11**
- Broken-policy unauthorized exposures: **6**

| Scenario | Category | Expected secure | Vulnerable | Secure | Result |
|---|---|---:|---:|---:|---:|
| Owner reads private document | authorized baseline | ALLOW | ALLOW | ALLOW | PASS |
| Tenant member reads shared document | authorized baseline | ALLOW | ALLOW | ALLOW | PASS |
| Administrator exports tenant data | authorized baseline | ALLOW | ALLOW | ALLOW | PASS |
| Analyst requests another user's private document | horizontal IDOR | DENY | ALLOW | DENY | PASS |
| Viewer modifies another user's document | horizontal privilege escalation | DENY | ALLOW | DENY | PASS |
| Analyst claims administrator role | vertical privilege escalation | DENY | ALLOW | DENY | PASS |
| Viewer directly browses user administration | forced browsing | DENY | ALLOW | DENY | PASS |
| Analyst reads another tenant's document | cross-tenant access | DENY | ALLOW | DENY | PASS |
| Disabled administrator uses an old session | session lifecycle | DENY | ALLOW | DENY | PASS |
| Anonymous user requests a document | missing authentication | DENY | DENY | DENY | PASS |
| Authenticated user requests an unknown endpoint | default deny | DENY | DENY | DENY | PASS |

## Secure Design Controls

1. Bind identity and role to trusted server-side sessions.
2. Check authorization for every endpoint and object operation.
3. Enforce tenant boundaries before ownership or role decisions.
4. Apply least privilege and deny unknown actions by default.
5. Test negative authorization cases as regression requirements.

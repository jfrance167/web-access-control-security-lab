# Web Access Control Security Lab

A safe, deterministic application-security lab that demonstrates broken access control and verifies a secure authorization design. It models authorization decisions locally and does **not** deploy an intentionally vulnerable internet-facing service.

## What the lab covers

- Horizontal privilege escalation and insecure direct object references (IDOR)
- Vertical privilege escalation through client-controlled roles
- Forced browsing to administrative endpoints
- Cross-tenant data access
- Disabled-session and anonymous-access handling
- Server-side identity, RBAC, ownership, tenant isolation, least privilege, and default denial

The scenarios align with OWASP A01: Broken Access Control and CWE-284, CWE-639, and CWE-862.

## Run the experiment

```bash
python access_control_lab.py samples/access-control-scenarios.json \
  --output reports/access-control-results.md \
  --fail-on-regression
```

Run the automated verification:

```bash
python -m unittest discover -s tests -v
python -m bandit -q -r access_control_lab.py tests
```

## Expected result

The vulnerable policy exposes six unauthorized paths. The secure policy produces the expected result for all eleven scenarios, including three legitimate requests that must remain available.

## Safe-use boundary

Use these concepts only in systems you own or are explicitly authorized to test. The project contains fictional identities and local policy models—no credentials, live targets, exploit automation, or destructive actions.

See [LAB_REPORT.md](LAB_REPORT.md), [THREAT_MODEL.md](THREAT_MODEL.md), and the generated [experiment results](reports/access-control-results.md).

## Repository map

```text
web-access-control-security-lab/
|-- .github/
|-- .gitignore
|-- LAB_REPORT.md
|-- README.md
|-- SECURITY.md
|-- THREAT_MODEL.md
|-- access_control_lab.py
|-- reports/
|-- samples/
`-- tests/
```

Follow the setup and safety boundaries above before running or deploying any code.

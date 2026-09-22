# SecureDeploy

**Pre-deployment security testing for modern applications.**

SecureDeploy runs a coordinated battery of security scans — static analysis, dependency audits, secret detection, DAST, TLS/header checks, and custom authorization tests — and produces a single PASS/FAIL verdict with a unified findings report. Plug it into your CI/CD pipeline to block deployments that introduce security regressions.

---

## Features

- **Multi-tool pipeline** — Trivy, Semgrep CE, Nuclei, and a built-in HTTP engine run concurrently and their findings are deduplicated into a single normalized list
- **Custom authorization tests** — YAML-based test specs verify that access control rules are enforced server-side; supports multiple identities, fixtures, and IDOR detection
- **Smart deduplication** — SHA-256 fingerprinting with URL normalization (`/students/42/grades` → `/students/{id}/grades`), plus fuzzy cross-tool correlation
- **Policy engine** — configurable block/warn/report thresholds per severity, CWE/CVE overrides, confidence adjustment, and accepted risks with expiry dates
- **Safety controls** — production environment requires explicit acknowledgement; DEEP profile is blocked against production; private IP scanning is opt-in
- **SARIF output** — findings map natively to GitHub Code Scanning; each tool produces a separate `runs[]` entry
- **Credential redaction** — AWS keys, bearer tokens, passwords, and cookies are redacted from all evidence before storage or display
- **Audit log** — append-only JSONL audit trail for compliance

---

## Scanners

| Scanner | What it finds | Requires |
|---|---|---|
| **Trivy** | CVEs in dependencies, container images, hard-coded secrets, IaC misconfigurations | Docker or native binary |
| **Semgrep CE** | SAST — SQL injection, XSS, hardcoded credentials, insecure patterns | Docker or native binary |
| **Nuclei** | DAST — CVEs, misconfigurations, exposed panels, CORS, security headers | Docker or native binary |
| **Built-in HTTP** | HTTPS enforcement, TLS expiry, security headers, cookie flags, CORS | None (pure Python) |

---

## Quick start

### Docker (recommended)

```bash
docker run --rm \
  -v $(pwd):/project \
  -e TEST_ALICE_EMAIL=alice@example.com \
  -e TEST_ALICE_PASSWORD=secret \
  ghcr.io/tambanivohitra007/securedeploy:latest \
  securedeploy test --profile quick
```

### Local install

```bash
pip install securedeploy
securedeploy test --profile quick
```

### From source

```bash
git clone https://github.com/tambanivohitra007/securedeploy
cd securedeploy
pip install -e ".[dev]"
securedeploy test --profile quick
```

---

## Configuration

Place a `securedeploy.yaml` in your project root:

```yaml
version: "1"

project:
  name: "My API"

target:
  url: "https://staging.myapp.example.com"
  environment: staging
  scope:
    include:
      - "staging.myapp.example.com"
    exclude:
      - "stripe.com"
      - "auth0.com"

source:
  path: "./src"

policy:
  on_finding:
    critical: block
    high: block
    medium: warn
    low: report
  on_tool_failure: warn

output:
  directory: "./securedeploy-reports"
  formats:
    - terminal
    - sarif
    - json
```

See [`examples/django-app/securedeploy.yaml`](examples/django-app/securedeploy.yaml) for a full annotated example.

---

## Scan profiles

| Profile | Tools | Use case |
|---|---|---|
| `quick` | Built-in HTTP + Trivy secrets | Fast pre-push check (~1 min) |
| `standard` | All tools, safe Nuclei tags | Pre-merge / pre-deploy (~5–10 min) |
| `deep` | All tools, extended Nuclei templates | Scheduled security audit (requires explicit acknowledgement) |

```bash
securedeploy test --profile standard
securedeploy test --profile deep   # prompts for confirmation
```

---

## Custom authorization tests

Define identity-aware HTTP test cases in YAML:

```yaml
# security-tests/authorization.yaml
suite: "Authorization and Access Control"

authorization_tests:

  - name: "Student cannot read another student's grades"
    severity: critical
    identity: "student_alice"
    request:
      method: GET
      path: /api/students/{{ fixtures.bob_student_id }}/grades
    expect:
      status: [403, 404]
      body_must_not_contain:
        - '"grade"'
        - '"score"'

  - name: "Student cannot self-assign admin role"
    severity: critical
    identity: "student_alice"
    request:
      method: PUT
      path: /api/students/{{ fixtures.alice_student_id }}
      body:
        name: "Alice"
        role: "admin"
    expect:
      status: [200, 400]
      body_must_not_contain:
        - '"role":"admin"'
```

Identities are defined separately and support `login_form`, `api_key`, `bearer_token`, `basic`, and `oauth2_client_credentials` auth flows:

```yaml
# security-tests/identities.yaml
identities:
  - id: "student_alice"
    auth:
      type: login_form
      url: /api/auth/login
      body:
        username: "${TEST_ALICE_EMAIL}"
        password: "${TEST_ALICE_PASSWORD}"
      token_path: "$.access_token"
      token_usage:
        header: "Authorization"
        prefix: "Bearer "
```

See [`examples/django-app/security-tests/`](examples/django-app/security-tests/) for complete examples.

---

## Policy engine

### Severity thresholds

```yaml
policy:
  thresholds:
    max_critical: 0   # any critical finding → FAIL
    max_high: 5
```

### CWE / CVE overrides

```yaml
policy:
  overrides:
    block_cve:
      - "CVE-2021-44228"   # Log4Shell — always block regardless of severity
    warn_cwe:
      - "CWE-200"          # Downgrade to WARN (won't trigger max_critical threshold)
    block_cwe:
      - "CWE-89"           # SQL injection — always block
```

### Accepted risks

```yaml
accepted_risks:
  - id: "AR-001"
    title: "Self-signed cert on staging"
    rule_id: "tls-cert-invalid"
    tool: "builtin"
    reason: "Staging uses self-signed cert. Production has a valid cert."
    accepted_by: "security@example.com"
    expires: "2027-01-01"
```

### Confidence adjustment

Automatically downgrades severity when confidence is below a threshold, preventing low-signal findings from blocking deploys:

```yaml
policy:
  confidence_adjustment:
    enabled: true
    block_only_if_confidence:
      critical: medium   # CRITICAL needs at least MEDIUM confidence to block
      high: high         # HIGH needs HIGH confidence to block
```

---

## CI/CD integration

### GitHub Actions

```yaml
- name: SecureDeploy security scan
  run: |
    docker run --rm \
      -v ${{ github.workspace }}:/project \
      -e TEST_ALICE_EMAIL=${{ secrets.TEST_ALICE_EMAIL }} \
      -e TEST_ALICE_PASSWORD=${{ secrets.TEST_ALICE_PASSWORD }} \
      ghcr.io/tambanivohitra007/securedeploy:latest \
      securedeploy test --profile standard

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: securedeploy-reports/results.sarif
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | PASS — no blocking findings |
| `1` | FAIL — policy violation |
| `2` | Error — configuration or runtime error |
| `3` | Tool error — one or more scanners failed |

---

## Reports

SecureDeploy writes reports to `./securedeploy-reports/` (configurable):

- `results.sarif` — SARIF 2.1.0, compatible with GitHub Code Scanning
- `results.json` — Full structured report
- Terminal — Rich-formatted summary with severity counts and blocking findings

---

## Production safety

Scanning a production environment requires an explicit acknowledgement in the config:

```yaml
target:
  environment: production

safety:
  production_acknowledgement: "I confirm authorization to test api.example.com"
```

The `deep` profile is always blocked against production environments, regardless of acknowledgements.

---

## Development

```bash
git clone https://github.com/tambanivohitra007/securedeploy
cd securedeploy
pip install -e ".[dev]"
pytest tests/unit/
```

The test suite covers fingerprinting, correlation, normalizers (Trivy/Semgrep/Nuclei), the policy engine, and the safety controller.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

**Third-party tool notices**: Semgrep rules are subject to the Semgrep Rules License (free for non-SaaS use). See [NOTICE](NOTICE) for details.

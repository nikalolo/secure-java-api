# secure-java-api

A small Spring Boot API that I harden step by step while learning DevSecOps.
Each phase adds a security practice and records the before/after evidence.

## Endpoints

| Method | Path | Response |
|---|---|---|
| GET | `/health` | `{"status":"UP"}` |

## Progress

| Phase | Practice | Status |
|---|---|---|
| 1 | Baseline: naive container + first Trivy scan | Done locally: 391 findings (8 CRITICAL, 134 HIGH), Spring Boot 3.5.7 |
| 2 | Container hardening | Done locally: 113 findings (8 CRITICAL, 19 HIGH), non-root, read-only FS, Spring Boot 3.5.7 |
| 3 | SAST (Semgrep), dependency and secret scanning | Done: app JAR 59 to 21 to 0 findings (Spring Boot 3.5.7 to 3.5.16 to 4.1.2), 0 secrets in history |
| 4 | CI/CD security gates | Done: actions and images pinned, protected `main` with 6 required checks, Dependabot, merge-blocking gates (Trivy, Semgrep, gitleaks, image, workflow lint); Scorecard 3.8 to 5.5, zizmor 17 to 0 |
| 5 | DAST (OWASP ZAP) | Planned |
| 6 | Cloud and IaC security | Planned |
| 7 | SBOM, signing, supply chain | Planned |

## Run locally

No Maven install needed: the Maven Wrapper downloads a pinned Maven 3.10.0
(checked against a SHA-256 in `.mvn/wrapper/maven-wrapper.properties`).
Use `./mvnw` on Linux/macOS/Git Bash and `.\mvnw.cmd` on Windows.

```bash
# Tests
./mvnw verify            # Windows: .\mvnw.cmd verify
python -m pip install --require-hashes -r tests/requirements.txt
python -m pytest tests

# Hardened image (builds the JAR inside Docker), run locked down
docker build -t secure-java-api:hardened -f Dockerfile.hardened .
docker run --rm -p 8080:8080 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL --security-opt no-new-privileges:true secure-java-api:hardened
curl http://localhost:8080/health

# Baseline image (for comparison; needs the JAR from ./mvnw package)
docker build -t secure-java-api:baseline .

# Code scan: Semgrep + Trivy on pom.xml and app.jar
# (needs Docker, jq, Python and ~/.m2 filled by this build)
./mvnw -B -ntp package -DskipTests
scripts/code-scan.sh

# One-off secret scan of the full local git history (gitleaks)
scripts/history-scan.sh
```

## CI workflows

Every change to `main` goes through a pull request. The jobs marked required must pass before it can
be merged (ruleset `protect-main`). The gate scripts exit with 10 on a security finding and with 1 on a
tool or network error, so the exit code of a red gate step shows which of the two it is.

| Workflow | Runs on | Job | Required | What it does | Fails on |
|---|---|---|---|---|---|
| `ci.yml` | pull requests, push to `main` | `java-tests` | yes | `./mvnw verify` | a failing test |
| | | `script-tests` | yes | pytest for `scripts/trivy_report.py`, installed from a hashed requirements file | a failing test |
| `code-scan.yml` | pull requests, push to `main`, daily, by hand | `scan` | yes | `scripts/code-scan.sh`: Semgrep, Trivy on `pom.xml`, `tests/requirements.txt` and `app.jar`, Trivy secret scan, canary checks | Trivy CRITICAL or HIGH; a secret; a Semgrep ERROR finding that is new since the base commit (not on the daily run, which has no new commit to compare) |
| | | `secrets` | yes | `scripts/history-scan.sh`: gitleaks over the full git history, with a built-in positive control | any leak |
| `hardened-scan.yml` | pull requests, push to `main`, daily, by hand | `compare` | yes | builds both images, runs the hardened one locked down (non-root, read-only filesystem), compares their Trivy results, then `scripts/image-gate.sh` | the hardened container running as root or with a writable filesystem; a CRITICAL with a fixed version in the hardened image |
| `workflow-lint.yml` | pull requests, push to `main`, by hand | `workflow-lint` | yes | `scripts/workflow-lint.sh`: actionlint (with ShellCheck) over the workflows, zizmor over the workflows and `dependabot.yml` | any actionlint problem; any zizmor finding at the default level (the stricter pedantic level is only printed) |
| `baseline-scan.yml` | push to `main`, started by hand | `build-and-scan` | no | builds the naive image, smoke-tests it, Trivy-scans it | nothing: report-only, it is the "before" evidence |

Accepted risks go in `.trivyignore`, each with a reason and a review date at most 90 days ahead. Details
and red tests for every gate: [Phase 4](docs/phase4-cicd-security.md).

## Evidence

- [Baseline image scan](docs/baseline-scan.md)
- [Baseline config scan (Checkov, actionlint)](docs/baseline-config-scan.md)
- [Phase 2: container hardening](docs/phase2-container-hardening.md)
- [Phase 3: SAST, dependency and secret scanning](docs/phase3-sast-sca.md)
- [Phase 4: CI/CD security](docs/phase4-cicd-security.md)

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
| 4 | CI/CD security gates | Planned |
| 5 | DAST (OWASP ZAP) | Planned |
| 6 | Cloud and IaC security | Planned |
| 7 | SBOM, signing, supply chain | Planned |

## Run locally

No Maven install needed: the Maven Wrapper downloads a pinned Maven 3.9.16
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

| Workflow | What it does |
|---|---|
| `ci.yml` | Java tests (`./mvnw verify`) and script tests (pytest) on every push/PR |
| `baseline-scan.yml` | Builds the naive image, smoke-tests it, Trivy-scans it |
| `hardened-scan.yml` | Builds both images, runs the hardened one locked down, asserts non-root and read-only FS, compares Trivy results |
| `code-scan.yml` | Runs `scripts/code-scan.sh` (Semgrep, Trivy on pom and JAR, secrets) with canary checks, on push to main and every PR |

## Evidence

- [Baseline image scan](docs/baseline-scan.md)
- [Baseline config scan (Checkov, actionlint)](docs/baseline-config-scan.md)
- [Phase 2: container hardening](docs/phase2-container-hardening.md)
- [Phase 3: SAST, dependency and secret scanning](docs/phase3-sast-sca.md)

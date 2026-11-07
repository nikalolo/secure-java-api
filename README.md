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
| 1 | Baseline: naive container + first Trivy scan | Done locally: 391 findings (8 CRITICAL, 134 HIGH) |
| 2 | Container hardening | Done locally: 113 findings (8 CRITICAL, 19 HIGH), non-root, read-only FS |
| 3 | SAST (Semgrep) and dependency scanning | Planned |
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
python -m pytest tests

# Hardened image (builds the JAR inside Docker), run locked down
docker build -t secure-java-api:hardened -f Dockerfile.hardened .
docker run --rm -p 8080:8080 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL --security-opt no-new-privileges:true secure-java-api:hardened
curl http://localhost:8080/health

# Baseline image (for comparison; needs the JAR from ./mvnw package)
docker build -t secure-java-api:baseline .
```

## CI workflows

| Workflow | What it does |
|---|---|
| `ci.yml` | Java tests (`mvn verify`) and script tests (pytest) on every push/PR |
| `baseline-scan.yml` | Builds the naive image, smoke-tests it, Trivy-scans it |
| `hardened-scan.yml` | Builds both images, runs the hardened one locked down, asserts non-root and read-only FS, compares Trivy results |

## Evidence

- [Baseline image scan](docs/baseline-scan.md)
- [Baseline config scan (Checkov, actionlint)](docs/baseline-config-scan.md)
- [Phase 2: container hardening](docs/phase2-container-hardening.md)

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
| 1 | Baseline: naive container + first Trivy scan | In progress |
| 2 | Container hardening | Planned |
| 3 | SAST (Semgrep) and dependency scanning | Planned |
| 4 | CI/CD security gates | Planned |
| 5 | DAST (OWASP ZAP) | Planned |
| 6 | Cloud and IaC security | Planned |
| 7 | SBOM, signing, supply chain | Planned |

## Run locally

```bash
mvn package
docker build -t secure-java-api:baseline .
docker run --rm -p 8080:8080 secure-java-api:baseline
curl http://localhost:8080/health
```

## Evidence

- [Baseline scan](docs/baseline-scan.md)

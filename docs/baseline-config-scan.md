# Baseline config scan (Dockerfile and workflows)

Static checks of the *configuration*, run before any hardening.
Complements the image scan in [baseline-scan.md](baseline-scan.md).

**Date:** 2026-11-01
**Tools:** Checkov 3.4.0 (`--framework dockerfile github_actions --skip-download`), actionlint 1.7.12 with ShellCheck 0.9.0
**Reproduce:** `scripts/config-scan.sh`

## Results

| Scope | Passed | Failed |
|---|---|---|
| `Dockerfile` | 3 | 2 |
| `.github/workflows/*.yml` | 84 | 0 |
| actionlint | — | 0 (1 ShellCheck warning found and fixed in `97c612f`) |

### Dockerfile failures

| Check | Meaning | Evidence | Planned fix |
|---|---|---|---|
| CKV_DOCKER_3 | No non-root `USER` | Dockerfile has no `USER` line, so the process runs as root | Phase 2 |
| CKV_DOCKER_2 | No `HEALTHCHECK` | No `HEALTHCHECK` instruction | Phase 2 (decide: HEALTHCHECK vs orchestrator probes) |

## What the scanner did *not* catch

A clean scanner result is not a clean bill of health. Known gaps, verified by reading the files:

- **Deprecated base image.** `openjdk:17` passed CKV_DOCKER_7 because it isn't `:latest`, but the Docker Hub `openjdk` image is deprecated and no longer updated ([Docker Hub page](https://hub.docker.com/_/openjdk), [docker-library/openjdk#505](https://github.com/docker-library/openjdk/issues/505)). Checkov checks the tag format, not whether the image is maintained.
- **Unpinned third-party code in CI.** Actions are referenced by tag (`actions/checkout@v5`) and Trivy runs as `aquasec/trivy:latest`. A moved tag can run different code in the pipeline. No Checkov GitHub Actions check flagged this. Planned for Phase 4 (pin by commit SHA / image digest).
- **Scanner network calls.** Checkov tries to contact its vendor API by default; `--skip-download` keeps it offline. Worth knowing before running vendor tools on private code.

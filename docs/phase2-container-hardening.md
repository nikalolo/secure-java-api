# Phase 2: Container hardening

**Goal:** reduce what an attacker can reach, and what they can do after a compromise.
Baseline: [`Dockerfile`](../Dockerfile). Hardened: [`Dockerfile.hardened`](../Dockerfile.hardened).
CI: [`hardened-scan.yml`](../.github/workflows/hardened-scan.yml) builds both, runs the hardened one locked down, and compares Trivy results.

## Image-level controls

| Control | Baseline | Hardened | Why it matters |
|---|---|---|---|
| Base image | `openjdk:17` (deprecated, unmaintained) | `eclipse-temurin:17-jre` (maintained) | Unmaintained images never get CVE fixes |
| JDK vs JRE | Full JDK | JRE only | No compiler or dev tools for an attacker to use |
| Build tools in image | n/a (built on runner) | Multi-stage: Maven/JDK stay in the build stage | Final image contains only what runs |
| Process user | root (UID 0) | `app`, UID 10001, no shell, no home | A code-execution bug doesn't hand out root |
| JAR ownership | root, writable by process | root-owned, read-only to the app user | Compromised process can't replace its own code |
| Build context | everything | [`.dockerignore`](../.dockerignore) excludes `.env`, keys, `.git` | Prevents secrets being copied into layers |
| JVM in containers | defaults | `MaxRAMPercentage=75`, `ExitOnOutOfMemoryError` | Respects memory limit; fails fast instead of degrading |
| HEALTHCHECK | none | none, skipped with justification | JRE image has no curl; CI/orchestrator checks `/health` instead of adding a tool |

## Runtime controls (`docker run` flags)

| Flag | Effect |
|---|---|
| `--read-only` | Root filesystem can't be written, even by root |
| `--tmpfs /tmp:rw,noexec,nosuid,size=64m` | Only `/tmp` is writable (Tomcat needs it); files there can't be executed |
| `--cap-drop ALL` | Removes all Linux capabilities (no raw sockets, no chown, no binding low ports…) |
| `--security-opt no-new-privileges:true` | setuid binaries can't raise privileges |
| `--memory 512m --pids-limit 200` | Limits damage from memory leaks and fork bombs |

## Evidence

### Verified locally (2026-11-01)

| Check | Result |
|---|---|
| Checkov on `Dockerfile.hardened` | 59 passed, 0 failed, 1 skipped (CKV_DOCKER_2, justified above) |
| Checkov on baseline `Dockerfile` | 3 passed, 2 failed (no USER, no HEALTHCHECK) — see [baseline-config-scan.md](baseline-config-scan.md) |
| `.dockerignore` | Scratch build of the context: `.env`, `*.key`, `target/classes` excluded; `target/app.jar` kept |
| Runtime flags (busybox test image, same flags) | UID 10001; root write to `/` refused (`Read-only file system`) while the same write succeeds without `--read-only`; `/tmp` writable; executing from `/tmp` refused (`Permission denied`) |

The local runtime test used a small busybox image because this sandbox cannot pull base images. The same assertions run against the real hardened image in CI.

### Pending first CI run

| Metric | Baseline | Hardened |
|---|---|---|
| CRITICAL | | |
| HIGH | | |
| MEDIUM | | |
| LOW | | |
| Image size | | |
| Container UID | | |

Filled from the `trivy-comparison` artifact of `hardened-scan.yml`.

## Deliberately deferred

- **Pinning base images and actions by digest/SHA** — Phase 4 (supply chain).
- **Failing the build on HIGH/CRITICAL** — Phase 4 (security gates). Today the scans report but never block.
- **Distroless/minimal runtime image** — revisit after seeing how many CVEs remain in the Temurin JRE image.

# Phase 2: Container hardening

**Goal:** reduce what an attacker can reach, and what they can do after a compromise.
Baseline: [`Dockerfile`](../Dockerfile). Hardened: [`Dockerfile.hardened`](../Dockerfile.hardened).
CI: [`hardened-scan.yml`](../.github/workflows/hardened-scan.yml) builds both, runs the hardened one locked down, and compares Trivy results.

## Image-level controls

| Control | Baseline | Hardened | Why it matters |
|---|---|---|---|
| Base image | `openjdk:17.0.2` (deprecated, unmaintained; `openjdk:17` itself was removed, see [baseline-scan.md](baseline-scan.md#note-openjdk17-no-longer-exists)) | `eclipse-temurin:17-jre` (maintained) | Unmaintained images never get CVE fixes |
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

### Real images, verified locally (2026-11-02)

Windows 11 + Docker Desktop 29.9.2, hardened image run with every flag above:

| Check | Result |
|---|---|
| `GET /health` / `POST /health` | `{"status":"UP"}` / 405 |
| `docker exec app id` | `uid=10001(app) gid=10001(app)` (baseline: `uid=0(root)`) |
| `ReadonlyRootfs` | `true`; `touch /pwned` as root refused: `Read-only file system` |
| `/app/app.jar` | owned by `0 0`, `-rw-r--r--`; append as app user refused: `Permission denied` |
| `/tmp` | write succeeds; running a copied binary refused (`Permission denied`, exit 126) |
| `/proc/1/status` | `CapEff: 0000000000000000`, `NoNewPrivs: 1` (baseline: `CapEff: 00000000a80425fb`) |

### Trivy comparison (local, 2026-11-02)

Trivy 0.76.1, both images scanned seconds apart with the same vulnerability DB.

| Metric | Baseline | Hardened |
|---|---|---|
| CRITICAL | 8 | 8 |
| HIGH | 134 | 19 |
| MEDIUM | 221 | 74 |
| LOW | 28 | 12 |
| **Total** | **391** | **113** |
| Image size | 732 MiB | 446 MiB |
| Container UID | 0 (root) | 10001 (app) |

Split by layer:

| Layer | Baseline | Hardened |
|---|---|---|
| OS packages | Oracle Linux 8.5: 0 C / 115 H / 200 M / 20 L, 335 of 335 fixable | Ubuntu 26.04: 0 C / 0 H / 53 M / 4 L, 0 of 57 fixable |
| `app.jar` | 8 C / 19 H / 21 M / 8 L, 56 of 56 fixable | identical |

All 8 CRITICAL and all 19 HIGH left in the hardened image are in `app.jar` (Tomcat 10.1.48, Spring
Framework 6.2.12, Spring Boot 3.5.7, Jackson 2.19.2): the image change can't remove them, only a
dependency upgrade can (Phase 3). Full list: [baseline-scan.md](baseline-scan.md#criticalhigh-in-appjar).
The CI run of `hardened-scan.yml` on 2026-11-08 (`trivy-comparison` artifact, Trivy 0.76.2, scanned 6 days later with a newer DB) found 416 / 118, not 391 / 113. The `app.jar` part is fully explained: 59 = these 56 plus 3 Tomcat CVEs added to the DB after 2026-11-02 (0 removed). The OS layers grew by 22 (baseline) and 2 (hardened); only counts can be compared there, because the local Phase 2 image JSON is no longer on disk.

## Deliberately deferred

- **Pinning base images and actions by digest/SHA** — Phase 4 (supply chain).
- **Failing the build on HIGH/CRITICAL** — Phase 4 (security gates). Today the scans report but never block.
- **Distroless/minimal runtime image** — revisit after seeing how many CVEs remain in the Temurin JRE image.

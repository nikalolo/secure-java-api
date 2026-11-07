# Baseline scan

**Image:** `secure-java-api:baseline` (base `openjdk:17.0.2`, Oracle Linux 8.5, JDK 17.0.2; see note below)
**Scanner:** Trivy 0.76.1 (`aquasec/trivy:latest`), JSON summarised by `scripts/trivy_report.py`
**Source:** local run, 2026-11-02 (Windows 11 + Docker Desktop 29.9.2). CI run of `baseline-scan.yml`: link to be added.
**Reproduce:** `./mvnw package`, `docker build -t secure-java-api:baseline .`, then the Trivy command in `baseline-scan.yml`.

Related: [config scan of the same Dockerfile](baseline-config-scan.md).

## Note: `openjdk:17` no longer exists

The original baseline used `FROM openjdk:17`. Building it on 2026-11-02 failed:

```
ERROR: failed to build: failed to solve: openjdk:17: failed to resolve source metadata
for docker.io/library/openjdk:17: docker.io/library/openjdk:17: not found
```

Docker Hub's API agrees: `GET /v2/repositories/library/openjdk/tags/17` returns **HTTP 404**, and no tag
starting with `17` is listed. The `openjdk` repository now publishes only early-access builds (`28-ea-*`).
The newest JDK 17 tag still on Docker Hub is `17.0.2` (last updated 2022-04-28), the last build the `17` tag
could have pointed to, so the baseline now uses `openjdk:17.0.2`.

This is the deprecation risk from the config scan in practice: an unmaintained base image eventually
stops getting fixes, and then it can disappear and break the build. `17.0.2` is just as deprecated,
unpatched, root and full-JDK as before. It keeps the "before" image buildable; it does not harden it.

## Results

| Severity | Count |
|---|---|
| CRITICAL | 8 |
| HIGH | 134 |
| MEDIUM | 221 |
| LOW | 28 |
| UNKNOWN | 0 |
| **Total** | **391** |

Findings with a fixed version available: 391 of 391.

| Layer | CRITICAL | HIGH | MEDIUM | LOW | Fixable |
|---|---|---|---|---|---|
| OS packages (Oracle Linux 8.5) | 0 | 115 | 200 | 20 | 335 of 335 |
| `app.jar` (Java libraries) | 8 | 19 | 21 | 8 | 56 of 56 |

- Image size: 732 MiB (`docker image inspect --format '{{.Size}}'`, as in CI)
- Container runs as: `uid=0(root) gid=0(root)` (`docker exec app id`)
- Other observations: `javac` present (full JDK); `/app.jar` is `-rwxr-xr-x root`, so the process
  (root) can rewrite its own code; default Docker capability set (`CapEff: 00000000a80425fb`)

## CRITICAL/HIGH in `app.jar`

These 27 come from the dependencies Spring Boot 3.5.7 brings in (Tomcat, Spring Framework, Jackson).
They are **identical in the hardened image** (same JAR). Fixing them is Phase 3 (SCA), not done here.

| # | CVE | Severity | Package | Installed | Fixed in |
|---|---|---|---|---|---|
| 1 | CVE-2026-41293 | CRITICAL | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 9.0.118, 10.1.55, 11.0.22 |
| 2 | CVE-2026-43512 | CRITICAL | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 9.0.118, 10.1.55, 11.0.22 |
| 3 | CVE-2026-43515 | CRITICAL | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 9.0.118, 10.1.55, 11.0.22 |
| 4 | CVE-2026-47884 | CRITICAL | `org.springframework:spring-webmvc` | 6.2.12 | 7.0.9 |
| 5 | CVE-2026-47890 | CRITICAL | `org.springframework:spring-webmvc` | 6.2.12 | 7.0.9 |
| 6 | CVE-2026-65182 | CRITICAL | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 11.0.25, 10.1.58, 9.0.121 |
| 7 | CVE-2026-65905 | CRITICAL | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 11.0.25, 10.1.58, 9.0.121 |
| 8 | CVE-2026-68525 | CRITICAL | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 11.0.25, 10.1.58, 9.0.121 |
| 9 | CVE-2026-24734 | HIGH | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 11.0.18, 10.1.52, 9.0.115 |
| 10 | CVE-2026-24880 | HIGH | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 9.0.116, 10.1.52, 11.0.20 |
| 11 | CVE-2026-34483 | HIGH | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 9.0.116, 10.1.54, 11.0.21 |
| 12 | CVE-2026-34487 | HIGH | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 9.0.117, 10.1.54, 11.0.21 |
| 13 | CVE-2026-40973 | HIGH | `org.springframework.boot:spring-boot` | 3.5.7 | 4.0.6, 3.5.14 |
| 14 | CVE-2026-41284 | HIGH | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 9.0.118, 10.1.55, 11.0.22 |
| 15 | CVE-2026-41842 | HIGH | `org.springframework:spring-webmvc` | 6.2.12 | 7.0.8, 6.2.19 |
| 16 | CVE-2026-41845 | HIGH | `org.springframework:spring-webmvc` | 6.2.12 | 7.0.8, 6.2.19 |
| 17 | CVE-2026-41850 | HIGH | `org.springframework:spring-expression` | 6.2.12 | 7.0.8, 6.2.19 |
| 18 | CVE-2026-42498 | HIGH | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 9.0.118, 10.1.55, 11.0.22 |
| 19 | CVE-2026-43513 | HIGH | `org.apache.tomcat.embed:tomcat-embed-core` | 10.1.48 | 9.0.118, 10.1.55, 11.0.22 |
| 20 | CVE-2026-54512 | HIGH | `com.fasterxml.jackson.core:jackson-databind` | 2.19.2 | 2.18.8, 3.1.4, 2.21.4 |
| 21 | CVE-2026-54513 | HIGH | `com.fasterxml.jackson.core:jackson-databind` | 2.19.2 | 2.18.8, 2.21.4, 3.1.4 |
| 22 | CVE-2026-68494 | HIGH | `com.fasterxml.jackson.core:jackson-core` | 2.19.2 | 2.18.8, 2.21.4 |
| 23 | CVE-2026-68497 | HIGH | `com.fasterxml.jackson.core:jackson-databind` | 2.19.2 | 2.18.10, 2.21.6, 2.22.2 |
| 24 | CVE-2026-89407 | HIGH | `com.fasterxml.jackson.core:jackson-core` | 2.19.2 | 2.18.11, 2.21.7, 2.22.3 |
| 25 | CVE-2026-89425 | HIGH | `com.fasterxml.jackson.core:jackson-core` | 2.19.2 | 2.21.7, 2.22.3, 2.18.11 |
| 26 | CVE-2026-91776 | HIGH | `com.fasterxml.jackson.core:jackson-databind` | 2.19.2 | 2.18.11, 2.21.7, 2.22.3 |
| 27 | CVE-2026-91777 | HIGH | `com.fasterxml.jackson.core:jackson-databind` | 2.19.2 | 2.21.7, 2.18.11, 2.22.3 |

"Fixed in" lists every release line Trivy knows a fix for. The two `spring-webmvc` CRITICALs have no
6.2.x fix listed, only 7.0.9 (the Spring Framework line used by Spring Boot 4).

## Analysis

_To be written by the owner (Task 1 questions)._

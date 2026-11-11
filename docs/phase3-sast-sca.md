# Phase 3: SAST, dependency scanning, secret scanning

**Goal:** find vulnerable code, vulnerable dependencies and leaked secrets, and prove each scanner really looked.
Local: [`scripts/code-scan.sh`](../scripts/code-scan.sh) (Semgrep + Trivy) and [`scripts/history-scan.sh`](../scripts/history-scan.sh) (gitleaks, one-off).
CI: [`code-scan.yml`](../.github/workflows/code-scan.yml) runs `code-scan.sh` on every push to main and every PR.
**Report-only:** findings never fail the build yet (Phase 4). Tool errors and canaries do.

## Tools

| Tool | Version, image | Scans | Why this one |
|---|---|---|---|
| Semgrep CE | 1.184.0, `semgrep/semgrep@sha256:cc1b6826...` | Our code, workflows, Dockerfiles, properties | Free, offline (`--metrics=off`, no login), custom rules are short YAML |
| Trivy | 0.76.2, `aquasec/trivy@sha256:8f6bb947...` | `pom.xml` (`fs`), the built `app.jar` (`rootfs`), secrets in tracked files | Already used for the images in Phases 1-2; reads both the pom and the JAR |
| gitleaks | v8.30.1, `ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0...` | Full local git history incl. the reflog | Scans every commit, not just the current tree. Now feature-complete (security patches only) |

Not chosen: OWASP Dependency-Check (needs an NVD API key, slow, CPE matching gives false positives).
Dependabot belongs to Phase 4 (update PRs, not scanning).

## Trusting the scanners

- **Digest pins.** In March 2026 the Docker Hub tags `aquasec/trivy:0.69.4`-`0.69.6` and `latest` served
  malicious images that stole CI secrets ([GHSA-69fq-xp46-6x23](https://osv.dev/vulnerability/GHSA-69fq-xp46-6x23)).
  A tag can be moved; a digest can't. All three scanner images are pinned `name:tag@sha256:...`.
- **Signature.** `cosign verify` (cosign v3.1.4) on the Trivy digest passed on 2026-11-11: signed by
  `aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.76.2`.
  A control run expecting `v0.76.1` failed, so the identity check is real.
- **Read-only repo.** Every scanner container mounts the repo `:ro` and writes only to a separate output mount.
- **No token on disk.** CI checks out with `persist-credentials: false`, so containers can't read a token from `.git/config`.

## Proving the scans ran

A scanner that silently scans nothing reports "0 findings" too. Each check below was made to fail once on purpose.

| Check | Proves | Tested failure |
|---|---|---|
| Semgrep canary: 6 rule IDs must fire on `.semgrep/canary/`, each proving a ruleset or rule ran | Each ruleset loaded and ran with the real command (same image, flags, mount, ignore file) | CI run with one canary file removed: red, `MISSING` for exactly its 2 IDs |
| `semgrep --test` on custom rules | Each rule matches its fixture | Mutation: one fixture annotation flipped each way (`ruleid:` to `ok:` in rule B, `ok:` to `ruleid:` in rule A); `--test` failed both times |
| Trivy canary: named packages in the JAR result, no empty versions in the pom result | Trivy resolved the dependencies | A directory with no jars: both JAR checks failed. An empty `~/.m2`: the pom check failed |
| Stale-JAR check: `BOOT-INF/lib/spring-boot-<pom version>.jar` must be in `app.jar` | The scanned JAR was built from this pom | pom 3.5.16 vs JAR 3.5.7: exit 1 |
| `~/.m2/repository` required, mounted read-only | `trivy fs --offline-scan` can resolve the pom (without it Trivy finds 2 packages with empty versions, 0 findings, exit 0) | Missing `~/.m2`: exit 1 |
| gitleaks commit count = commits with an added line in `git log --all --reflog` | gitleaks read the whole history (it exits 0 and says "no leaks found" when git fails) | Trailing space in `--log-opts`: `ERR`, exit 1 |
| gitleaks positive control (built at runtime): fake key added, then deleted, plus an empty commit | Detection works on history, redaction works | Must find 1 leak in 2 scanned commits, report `REDACTED`, key absent from report and log |
| `trivy_report.py` diff key (unit test) | A version bump compares by (CVE, package) | Version put back into the key: the new test fails |

`p/java` has no canary of its own: all its 60 rules are also in `p/owasp-top-ten` (559 rules, pack contents
fetched 2026-11-10), so no file can fire `p/java` alone. It is kept, but adds no coverage today.
In CI, `shell: bash` is set explicitly: the default `bash -e` has no `pipefail`, so `code-scan.sh | tee` would hide a failure.

## SAST results (Semgrep)

Semgrep 1.184.0, rulesets `p/java`, `p/owasp-top-ten`, `p/github-actions`, the single rule
`r/java.spring.security.unrestricted-request-mapping.unrestricted-request-mapping` (in no pack we use) and 2 custom rules.
28 files scanned (canary excluded; CI and local lists identical). Unique rule IDs are reported, not raw counts, because the packs overlap.

| Rule | Hits | Where | Status |
|---|---|---|---|
| `github-actions-mutable-action-tag` | 13 | Actions referenced by tag (`@v5`) in all 4 workflows | Phase 4: pin by commit SHA |
| `docker-image-without-digest` (custom B) | 3 | `aquasec/trivy:latest` in `baseline-scan.yml` (2) and `hardened-scan.yml` (1) | Phase 4: digest pins, expect 3 to 0 |
| `missing-user-entrypoint` | 1 | `Dockerfile:23` (no `USER`) | Intentional: the naive baseline |
| **Total** | **17** | 3 rules, 0 Semgrep errors | 0 in the application's Java code |

## Custom rules

| Rule | Matches | Known gaps |
|---|---|---|
| B `docker-image-without-digest` | An image ref `ns/name:tag` not followed by `@sha256:` in any `*.yml`, `*.yaml` or `*.sh` file. Matches the ref token, because refs often sit on continuation lines | Untagged refs (`ns/name`), official images without a namespace |
| A `spring-error-details-exposed` | `server.error.include-stacktrace` set to `always` or `on_param`, or `server.error.include-message=always`, in `.properties` files | `application.yml` needs its own pattern. 0 hits in the app; Phase 5 (ZAP) can confirm from outside |

## Dependency scanning: repo vs JAR

The pom (what we asked for) and the JAR (what Maven actually packaged) are scanned separately.

- **Cross-check on the Phase 1 databases** (vuln DB 2026-11-02T13:15Z, Java DB 2026-11-02T01:21Z, updates frozen):
  `rootfs` on `app.jar` and `fs` on `pom.xml` both gave 8 C / 19 H / 21 M / 8 L = 56, the same set of
  (CVE, package, version) and identical to the Phase 1 `app.jar` layer.
- **Package differences:** 5 `spring-boot-starter*` only in the pom (repackaging leaves starters out of `BOOT-INF/lib`),
  `spring-boot-jarmode-tools` only in the JAR (added by the Boot plugin).
- **Detection limit:** on 3.5.7, 16 of the 30 jars in `BOOT-INF/lib` (all `spring-*`, `tomcat-embed-*`, `micrometer-*`) have no
  `pom.properties`. Trivy identifies them only by SHA1 lookup in its Java DB.
- **Test scope** (`spring-boot-starter-test`) is not seen by either scan.

## Secrets

- **Trivy secret scan:** 0 in tracked files (CI on a clean checkout is the official number).
- **gitleaks, full local history:** 2026-11-11, `--all --reflog`, 52 of 52 expected commits scanned
  (55 in total; 3 are empty and gitleaks skips commits without added lines), 0 leaks.
- **Rewritten history is not private history.** After force-pushes, the replaced commits were no longer on any branch,
  but GitHub still served them by SHA to anyone, without login. Rewriting history does not take old commits off GitHub.
  The fix was deleting and recreating the repository and pushing only the clean branch (verified: the old SHAs now return 422).
  Copies in third-party archives are outside our control.

## Dependency upgrades: before and after

Each bump was scanned before and after in one sitting, with the Trivy DBs frozen for the "after" run, so only the code changed.
`app.jar` and `pom.xml` gave identical numbers every time.

| Spring Boot | CRITICAL | HIGH | MEDIUM | LOW | Total | DBs (vuln / Java) |
|---|---|---|---|---|---|---|
| 3.5.7 | 9 | 20 | 22 | 8 | **59** | 2026-11-10T19:01Z / 2026-11-10T00:57Z |
| 3.5.16 | 7 | 6 | 8 | 0 | **21** | same |
| 4.1.2 | 0 | 0 | 0 | 0 | **0** | same |
| 4.1.2, CI | 0 | 0 | 0 | 0 | **0** | 2026-11-11T13:00Z / 2026-11-11T01:07Z |

The same JAR had 56 findings on the Phase 1 DB and 59 on the newer one: 3 new Tomcat CVEs, with no code change.

**3.5.7 to 3.5.16** (patch releases only, no dependency overrides): 40 fixed, 19 remained, 2 new.

- The 19 survivors were predicted before the bump from each finding's fixed version; the result matched ID for ID.
  The 2 `spring-webmvc` CRITICALs (CVE-2026-47884, CVE-2026-47890) are fixed only in Spring Framework 7.0.9:
  no 3.5.x release can fix them, and 3.5 open-source support ended 2026-06-30.
- 2 new findings came with the newer versions: CVE-2026-65637 (CRITICAL, Tomcat 10.1.55) and GHSA-mhm7-754m-9p8w
  (MEDIUM, jackson-databind 2.21.4). A patch upgrade fixes what was known when it shipped and can bring new findings.

**3.5.16 to 4.1.2** (major upgrade): 21 to 0.

- Code changes: `spring-boot-starter-web` to `spring-boot-starter-webmvc`, `spring-boot-starter-test` to
  `spring-boot-starter-webmvc-test`, and the `@WebMvcTest` import (now `org.springframework.boot.webmvc.test.autoconfigure`).
  The test bodies didn't change and still pass (200, 405, 404).
- 10 fixed by upgrading past the fixed version: Tomcat 11.0.27 (7), Spring Framework 7.0.10 (2), log4j-api 2.25.5 (1).
- 11 Jackson findings: Jackson 3 moved to new package names (`tools.jackson.core`), so a comparison by package would drop them
  whether fixed or not. Compared by CVE ID instead: 8 of the IDs also exist for Jackson 3 and are fixed at or below 3.1.7
  (the version 4.1.2 ships); the other 3 are not reported for Jackson 3. No CVE ID carried over.
- **Why 0 is a result and not a blind spot:** all 34 jars in `BOOT-INF/lib` matched a Trivy package whose name and
  version equal the jar's file name, with a group set. And a test SBOM with older versions on the same lines (Tomcat 11.0.20, Jackson 3.1.0, Spring MVC 7.0.8)
  gave 16, 15 and 2 findings on the same frozen DB, so the DB does cover these version lines.

## Images after the upgrades

CI image scans of the 4.1.2 JAR (2026-11-11, fresh DB), compared with Phase 2 (Spring Boot 3.5.7, local, 2026-11-02):

| Image | Phase 2 | Now | CRITICAL now | From `app.jar` now |
|---|---|---|---|---|
| Baseline (`openjdk:17.0.2`, Oracle Linux 8.5) | 391 | 369 (115 H / 234 M / 20 L) | 0 | 0 |
| Hardened (`eclipse-temurin:17-jre`, Ubuntu 26.04) | 113 | 63 (2 H / 56 M / 4 L / 1 unknown) | 0 | 0 |

Everything left is in the base images: OS packages (the 2 HIGH are CVE-2026-109518 in `apt`) and a Go binary
(`/usr/bin/pebble`). Dependency upgrades can't fix those; base image updates can.

## Limits

- Numbers are dated: the vulnerability DBs change daily, so the same code gets new findings (59 vs 56 above).
- Semgrep counts are not upgrade results: Semgrep scans our code and workflows, not dependencies.
- Local scans also see untracked files; the CI run on a clean checkout is the official number.
- Test-scope dependencies are not scanned.
- Spring Boot 4.1 open-source support runs to 2027-07; staying at 0 needs regular upgrades.

## Deliberately deferred (Phase 4)

- Fail the build on HIGH/CRITICAL (the app JAR is at 0 now, so a gate is realistic).
- Pin actions by commit SHA and the remaining images by digest (Semgrep should drop to 1 finding).
- Dependabot for update PRs; `ci.yml` still calls `mvn` instead of `./mvnw`.
- `baseline-scan.yml` and `hardened-scan.yml` don't run on PRs.
- Base image findings: digest pins plus a rebuild cadence.

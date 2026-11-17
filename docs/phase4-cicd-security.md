# Phase 4: CI/CD security

**Goal:** make the pipeline itself hard to tamper with: protected main branch, every action and image pinned
by SHA or digest, automated update PRs, and scans that can fail a build.
**Status:** in progress. This file starts with the "before" numbers; each step adds its "after".

## Baseline

Measured on 2026-11-12 against `main` @ `748436f`, before any Phase 4 change. The tools only read.

| Tool | Version | Looks at | How it was run |
|---|---|---|---|
| OpenSSF Scorecard | v5.6.0 (release binary, SHA256 checked against `scorecard_checksums.txt`) | The GitHub repo: settings, workflows, history | `scorecard --repo=github.com/nikalolo/secure-java-api --format json --show-details` on Linux (WSL) |
| zizmor | 1.32.0 (PyPI) | `.github/workflows/*.yml` | `zizmor --persona <p> --format json .github/workflows` for the regular, pedantic and auditor personas, each with a GitHub token (online audits) and with `--offline` |
| Semgrep | 1.184.0 (digest-pinned image) | workflows, Dockerfiles, code | [`scripts/code-scan.sh`](../scripts/code-scan.sh), same command as Phase 3 |

### Scorecard: 3.8 / 10

Scorecard gives each check 0-10; `?` means Scorecard could not score the check (nothing to evaluate yet).
Tracked in this phase: Pinned-Dependencies, Token-Permissions, Branch-Protection, Dangerous-Workflow and
Dependency-Update-Tool. The overall score is context only.

| Check | Score | Reason reported | Phase 4 |
|---|---|---|---|
| Binary-Artifacts | 10 | no binaries in the repo | - |
| CI-Tests | 10 | 4 of 4 merged PRs checked by CI | - |
| Dangerous-Workflow | 10 | no dangerous workflow patterns | - |
| Token-Permissions | 10 | all 4 workflows set top-level `contents: read`, no job-level write | already done in Phases 1-3 |
| Vulnerabilities | 10 | 0 open vulnerabilities | - |
| Branch-Protection | 0 | branch protection not enabled on `main` | step 1 |
| Pinned-Dependencies | 0 | 0 of 13 actions, 0 of 3 Dockerfile base images, 0 of 1 `pip install` pinned by hash | step 2 |
| Dependency-Update-Tool | 0 | no update tool detected | step 3 |
| SAST | 0 | 0 of 7 commits checked with a SAST tool | see note |
| Code-Review | 0 | 0 of 21 changesets approved | see note |
| License | 0 | no license file | - |
| Security-Policy | 0 | no security policy file | - |
| Maintained | 0 | repo created within the last 90 days | time only |
| CII-Best-Practices | 0 | no OpenSSF best practices badge | - |
| Contributors | 0 | 0 contributing organizations | - |
| Fuzzing | 0 | not fuzzed | - |
| Packaging | ? | no packaging workflow | - |
| Signed-Releases | ? | no releases | Phase 7 |

Notes:

- **SAST is 0 although Semgrep runs on every push to `main` and on every PR.** Scorecard reported 0 of 7
  commits checked by a SAST tool, so the Semgrep run in `code-scan.yml` (a container started from a shell
  script) was not counted. The output does not say why.
- **Code-Review counts approvals.** Scorecard found 0 of 21 changesets with an approving review. This is a
  one-person repo, so no change gets one.
- **Pinned-Dependencies:** in this run it reported `uses:` lines, Dockerfile `FROM` lines and one
  `pip install`. It reported nothing about images started with `docker run` inside workflow steps. Those
  are covered by the Semgrep rule below.

### zizmor: 17 findings (regular persona)

| Audit | Severity | Count | Where |
|---|---|---|---|
| `unpinned-uses` | High | 13 | every `uses:` in the 4 workflows (tags like `@v5`) |
| `artipacked` | Medium | 4 | checkouts without `persist-credentials: false`: `ci.yml` (2), `baseline-scan.yml`, `hardened-scan.yml` |

| Persona | Offline | Online |
|---|---|---|
| regular | 17 | 17 |
| pedantic | 26 | 26 |
| auditor | 26 | 26 |

Pedantic and auditor add the same 9 lower findings: `concurrency-limits` (Low, 4) and
`anonymous-definition` (Informational, 5). The auditor persona found nothing beyond pedantic.

### Semgrep: 17 findings

Re-run on 2026-11-12 with Semgrep 1.184.0: 17 findings from 3 rules, 0 errors, 6 of 6 canaries fired,
30 files scanned (including this document; the 2026-11-11 run had 28).
Same findings as the Phase 3 run on 2026-11-11.

| Rule | Severity | Count | Where |
|---|---|---|---|
| `github-actions-mutable-action-tag` | WARNING | 13 | the same 13 `uses:` lines |
| custom rule: Docker image without `@sha256` in workflow and shell files | WARNING | 3 | `aquasec/trivy:latest` in `baseline-scan.yml` (2) and `hardened-scan.yml` (1) |
| `missing-user-entrypoint` | ERROR | 1 | `Dockerfile:23`, the deliberately naive baseline image |

The same script run also gave the Trivy numbers the step 4 gate starts from: `app.jar` and `pom.xml`
0 findings, secrets 0 (Trivy 0.76.2, vulnerability DB of 2026-11-10, frozen with `TRIVY_SKIP_DB_UPDATE=true`).
The image scans were not re-run for this baseline.

### Own counts

Counted from the files on `main` @ `748436f`.

| What | Count | Where |
|---|---|---|
| Actions referenced by tag, not SHA | 13 of 13 | all 4 workflows |
| Images in workflow steps without a digest | 3 | `baseline-scan.yml:60`, `:65`, `hardened-scan.yml:87` |
| `FROM` lines without a digest | 3 of 3 | `Dockerfile:14`, `Dockerfile.hardened:6`, `:20` |
| Workflows without a `pull_request` trigger | 2 of 4 | `baseline-scan.yml`, `hardened-scan.yml` |
| Workflows calling `mvn` instead of `./mvnw` | 3 of 4 | `ci.yml:23`, `baseline-scan.yml:31`, `hardened-scan.yml:32` |
| Jobs on `ubuntu-latest` | 5 of 5 | all jobs |
| Jobs with `timeout-minutes` | 1 of 5 | `code-scan.yml` |
| Workflows with a `concurrency` group | 0 of 4 | - |
| Jobs with their own `permissions` block | 0 of 5 | all 4 workflows set it at the top level only |
| Checkouts with `persist-credentials: false` | 1 of 5 | `code-scan.yml` |

### Check names on main

The names a ruleset has to list. All come from GitHub Actions.

| Workflow | Job = check name | Runs on PRs |
|---|---|---|
| `ci.yml` | `java-tests` | yes |
| `ci.yml` | `script-tests` | yes |
| `code-scan.yml` | `scan` | yes |
| `baseline-scan.yml` | `build-and-scan` | no |
| `hardened-scan.yml` | `compare` | no |

### Repository settings

Read from the GitHub API on 2026-11-12.

| Setting | Value |
|---|---|
| Rulesets / branch protection on `main` | none |
| Default workflow token permissions | read |
| Workflows may approve PRs | no |
| Allowed actions | all |
| Require actions pinned to a full SHA | off |
| Secret scanning, push protection | on, on |
| Dependabot alerts, security updates | off, off |
| Merge methods allowed | merge commit, squash, rebase |
| Delete head branch on merge | off |

### Gotcha: Scorecard on Windows

The Windows build of Scorecard v5.6.0, run on the same commit, reported "no workflows found" for
Dangerous-Workflow and "No tokens found" for Token-Permissions, listed only the 3 Dockerfile images under
Pinned-Dependencies, and scored 2.3. The repo has 4 workflows. The Linux binary found all of them, so the
numbers above come from the Linux run.

## Step 1: protect main

Done on 2026-11-12. The ruleset was created by hand in the repository settings. The values below were read
back from the GitHub API on 2026-11-13. Times are UTC.

### Ruleset `protect-main`

Active, targets the default branch, created 2026-11-12 16:32:11. There is no classic branch protection
next to it.

| Rule | Setting |
|---|---|
| Bypass list | empty; the API reports `current_user_can_bypass: never`, so the owner goes through a PR too |
| Restrict deletions | on |
| Block force pushes | on |
| Require linear history | on |
| Require a pull request before merging | on, 0 required approvals |
| Allowed merge methods | squash only |
| Conversations must be resolved before merging | on |
| Dismiss stale approvals, code owner review, approval of the last push | off |
| `require_extra_approval_for_unattributed_changes` | on (one more required review for pull requests that are not attributed to a person) |
| Require status checks to pass | `java-tests`, `script-tests`, `scan`, all three from GitHub Actions |
| Branch must be up to date before merging | on |
| Do not require status checks on creation | off |

Two choices that differ from the usual advice:

- **0 required approvals.** GitHub does not let the author approve their own pull request. In a one-person
  repo with an empty bypass list, a required approval would block every merge.
- **3 required checks, not 5.** `build-and-scan` and `compare` do not run on pull requests (see "Check names
  on main"). A required check that never reports stays pending, so requiring them would block every PR.

The repository settings still allow merge commits and rebase merges. On `main` the ruleset narrows that to
squash.

### Tests

| # | When | Test | Result |
|---|---|---|---|
| 1 | 16:25 | Direct push of the 3 baseline commits to `main` | **Accepted** (`748436f..078d798`). The ruleset did not exist yet |
| 2 | 16:32:57 | Direct push of a new, empty commit (`64dc95f`) to `main` | Rejected (GH013 in the terminal). Failed rules: `pull_request` "Changes must be made through a pull request." and `required_status_checks` "3 of 3 required status checks are expected." |
| 3 | 16:33:49 | Force push of a rewritten tip (`7fc58a7`, an amended copy of `078d798`) to `main` | Rejected (GH013 in the terminal). Failed rules: `non_fast_forward` "Cannot force-push to this branch", plus the same two as in test 2 |

The times and rule results of tests 2 and 3 come from GitHub's own record of the two pushes (rule suites
`5076113158` and `5076134590`, read from the API on 2026-11-13). In test 2 `non_fast_forward` is listed as
passed, in test 3 as failed, so the force-push rule fired on its own and not only the pull request rule.

After tests 2 and 3, `main` on GitHub was still at `078d798`, and the repository's activity log shows the
16:25 push as the last change to `main` (checked 2026-11-13).

What the tests show, and what they do not:

- **Test 1 ran 7 minutes before the ruleset existed, so it says nothing about the ruleset.** It is also how
  the three baseline commits (`9115e11`, `d2678e6`, `078d798`) reached `main`: by direct push, without a
  pull request. The 4 workflows ran on that push and passed, but after the fact, not as a gate. The commits
  stay as they are: rewriting them would take a force push to `main`.
- **In both tests the rejected push still uploaded its commit.** GitHub returns `64dc95f` and `7fc58a7` by
  full SHA (API and commit page, HTTP 200, checked 2026-11-13) although no branch contains them. Here the
  ruleset stopped the branch from moving, not the upload. Both commits are harmless (an empty commit, and
  the same files as `078d798`), but anything in a rejected push should be treated as published.
- **Not tested yet:** anything on the pull request path, because no PR has been opened since the ruleset
  was created: a merge with green checks, a failing required check, squash-only, the up-to-date
  requirement. Also not tested: deleting `main` (if the rule were missing, the test would delete the
  branch). Update 2026-11-14: a merge with green checks and a failing required check have now been
  seen on real PRs, see "CI results" and "Red test" in step 2.

Scorecard's Branch-Protection score will be measured again with the other checks at the end of the phase.

## Step 2: pin everything

Changed on 2026-11-13 on the branch `phase4/step1-2`. The numbers below are local runs on that branch.
The CI runs, the red test and the Scorecard result from 2026-11-14 follow further down.

### What is pinned

SHAs were read with `git ls-remote --tags`, digests with `docker buildx imagetools inspect`, both on
2026-11-13. Image digests are index digests, so they cover every platform of the tag.

| What | Before | After |
|---|---|---|
| `actions/checkout` (5 uses) | `@v5` | `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09` (v5.1.0) |
| `actions/setup-java` (4) | `@v5` | `b6effb05e454b25005698d916606bdc6ffcbf961` (v5.7.0) |
| `actions/setup-python` (1) | `@v6` | `ece7cb06caefa5fff74198d8649806c4678c61a1` (v6.3.0) |
| `actions/upload-artifact` (3) | `@v4` (targets Node 20) | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` (v7.0.2, Node 24) |
| Trivy in `baseline-scan.yml`, `hardened-scan.yml` | `aquasec/trivy:latest` | `aquasec/trivy:0.76.2@sha256:8f6bb947...` |
| `Dockerfile` | `openjdk:17.0.2` | `...@sha256:52870708...` |
| `Dockerfile.hardened`, build stage | `maven:3.9-eclipse-temurin-17` | `...@sha256:1a352420...` |
| `Dockerfile.hardened`, runtime stage | `eclipse-temurin:17-jre` | `...@sha256:0b652128...` |
| Runner | `ubuntu-latest` | `ubuntu-24.04` |
| Maven in CI | `mvn` from the runner | `./mvnw` (Maven 3.9.16, SHA-256 in `maven-wrapper.properties`) |
| pytest in CI | `pip install pytest==9.2.0` | `pip install --require-hashes --only-binary :all: -r tests/requirements.txt` |

- **Only one action version changed.** For checkout, setup-java and setup-python the SHA is the commit the old
  tag pointed to on 2026-11-13, so the same code runs as before. `upload-artifact` moved from v4 to v7.0.2
  because v4 targets the deprecated Node 20 (the runner already forces it onto Node 24 and prints a
  warning). Newer majors of the other three are left for the update PRs planned in step 3.
- **The Maven version changed in three workflows.** `ci.yml`, `baseline-scan.yml` and `hardened-scan.yml`
  used the runner's Maven (3.10.0 on the `ubuntu-24.04` image 20261111.370). They now use the wrapper's
  3.9.16, as `code-scan.yml` already did.
- **Trivy did not change.** On 2026-11-13 `aquasec/trivy:latest` resolved to the same digest as
  `0.76.2`, the one `scripts/code-scan.sh` already pins and that passed `cosign verify` in Phase 3.
- **The baseline `Dockerfile` is pinned too, and stays naive.** `openjdk:17` already disappeared from
  Docker Hub once. The digest keeps the "before" image reproducible. It is still the same deprecated,
  unpatched image running as root.
- **`tests/requirements.txt`** is generated from `tests/requirements.in` with
  `uv pip compile --universal --python-version 3.12 --generate-hashes`: 6 packages, 12 hashes. Because of
  its name, the existing `trivy fs` scan now covers these packages too (6 packages, 0 findings), so the
  comparison table is now titled "Repo (pom.xml + tests/requirements.txt) vs app.jar".

### Before and after (local)

| Metric | Before | After |
|---|---|---|
| zizmor regular | 17 | 4 (`unpinned-uses` 13 to 0; `artipacked` 4 planned for step 5) |
| zizmor pedantic | 26 | 13 |
| Semgrep findings | 17 | 1 (`missing-user-entrypoint`, `Dockerfile:23`) |
| Semgrep `github-actions-mutable-action-tag` | 13 | 0 |
| Custom rule, Docker image without `@sha256` | 3 | 0 |
| Actions referenced by tag | 13 of 13 | 0 of 13 |
| `FROM` lines without a digest | 3 of 3 | 0 of 3 |
| Workflows calling `mvn` | 3 of 4 | 0 of 4 |
| Jobs on `ubuntu-latest` | 5 of 5 | 0 of 5 |

zizmor 1.32.0 gave the same numbers offline and online and read all 4 workflows. Semgrep 1.184.0: 6 of 6
canaries fired, 0 errors, 32 files scanned (30 plus the two requirements files).

Other local checks on 2026-11-13:

- `./mvnw -B -ntp verify`: 3 tests, 0 failures.
- Fresh virtual environment, the install command above, then pytest: 11 passed. With one hash changed, pip
  refused to install ("THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE").
- Both images build from the pinned Dockerfiles. The hardened container, started with the locked-down
  flags, answered `/health` with `{"status":"UP"}`, ran as UID 10001 and refused a write to `/` as root.
- actionlint 1.7.12 (without ShellCheck): no issues. Checkov 3.4.0: GitHub Actions 172 passed, 0 failed;
  Dockerfiles 62 passed, 2 failed, both on the baseline `Dockerfile` (`CKV_DOCKER_2`, `CKV_DOCKER_3`).
- Trivy 0.76.2 on `pom.xml`, `tests/requirements.txt` and `app.jar`: 0 findings, secrets 0 (vulnerability
  DB of 2026-11-10, updates frozen).

### CI results (2026-11-14)

PR #5 was the first pull request through the `protect-main` ruleset. It was squash-merged on 2026-11-14
as `8a27800` with all three required checks green.

| Workflow | Run on the PR head `f9c9079` | Run on `main` @ `8a27800` |
|---|---|---|
| CI (`java-tests`, `script-tests`) | 43584205256 | 43586264299 |
| Code scan (`scan`) | 43584205218 | 43586264267 |
| Baseline image scan | 43584204779 (dispatched on the branch) | 43586264252 |
| Hardened image scan | 43584218183 (dispatched on the branch) | 43586264310 |

All eight runs succeeded. Details below are from the logs and artifacts of these runs.

- **Hashed install on Linux.** `script-tests` ran on Python 3.12.16 and installed 5 wheels (iniconfig,
  packaging, pluggy, pygments, pytest 9.2.0) with `--require-hashes --only-binary :all:`, then 11 tests
  passed. The sixth package in `tests/requirements.txt`, colorama, is marked Windows-only, and pip printed
  `Ignoring colorama: markers 'sys_platform == "win32"' don't match your environment`.
- **Maven wrapper.** `java-tests` ran 3 tests with 0 failures through `./mvnw`. The log shows a cache hit
  for the wrapper's Maven distribution, which is the case described under "What pinning does not cover".
- **`upload-artifact` v7.0.2.** The three artifacts (`code-scan`, `trivy-baseline`, `trivy-comparison`)
  hold 13 files, the same file names as the artifacts of the last run with v4 (`main` @ `078d798`).
  On `078d798` the three uploading jobs carried the annotation "Node.js 20 is deprecated", and all five
  jobs carried the notice that `ubuntu-latest` will migrate to Ubuntu 26. All five jobs on the PR head
  have 0 annotations.
- **Code scan.** Semgrep 1.184.0: 1 finding outside the canary (`missing-user-entrypoint`, `Dockerfile:23`),
  6 of 6 canaries, 0 errors, 32 files. Trivy 0.76.2: repo 0, `app.jar` 0, secrets 0 (vulnerability DB
  updated 2026-11-14T07:01Z). Same as the local run.

Image scans, compared with the last run before the pins (`main` @ `078d798`, 2026-11-12, images pulled
by tag):

| Image | 2026-11-12, by tag | 2026-11-14, by digest |
|---|---|---|
| Baseline, total | 381 | 381 |
| Baseline, C / H / M / L / UNKNOWN | 0 / 127 / 234 / 20 / 0 | 0 / 126 / 235 / 20 / 0 |
| Hardened, total | 35 | 61 |
| Hardened, C / H / M / L / UNKNOWN | 0 / 0 / 30 / 4 / 1 | 0 / 0 / 56 / 4 / 1 |

- **The pins did not change the base images.** The base image layers recorded in the Trivy reports are
  identical in both runs (3 of 3 for `openjdk:17.0.2`, 6 of 6 for `eclipse-temurin:17-jre`). Every
  difference in the table comes from the vulnerability database, which each run downloads fresh.
- **Baseline:** the same 381 findings. One, CVE-2026-33416 in `libpng`, was re-rated from HIGH to MEDIUM.
- **Hardened:** 26 new MEDIUM findings and none removed. 24 are 6 glibc CVEs, each reported on 4 packages
  (`libc6`, `libc-bin`, `libc-gconv-modules-extra`, `locales` at 2.43-2ubuntu2.4, fixed in
  2.43-2ubuntu2.7). 2 are CVE-2026-121876 in `libsystemd0` and `libudev1`, published 2026-11-12, with no
  fixed version yet. 26 of the 61 findings now have a fix available.
- **Java findings: 0 in both images.** The single UNKNOWN is in a Go binary that ships in the base image.
- The PR-head runs and the runs on `main` report the same findings for both images.

The runtime base image is behind on glibc fixes, but the pin has not caused that yet: on 2026-11-14 the
tag `eclipse-temurin:17-jre` still resolved to the pinned digest, so a build by tag would get the same
image. Once upstream rebuilds, the pin will hold the old image until the digest is updated, which is the
last point of "What pinning does not cover". Nothing fails on severity yet (step 4), and the update PRs
are planned for step 3.

### Red test: the SHA pinning setting

After the merge, the repository setting "Require actions to be pinned to a full-length commit SHA" was
turned on (2026-11-14; the API reports `sha_pinning_required: true`). To prove that it enforces, PR #6
changed one line on a throwaway branch: the checkout in the `script-tests` job of `ci.yml` went back to
`actions/checkout@v5`.

- **CI run 43587570486 failed.** `script-tests` stopped in "Set up job", before any step ran, with:
  `The action actions/checkout@v5 is not allowed in nikalolo/secure-java-api because all actions must be
  pinned to a full-length commit SHA.`
- **The check is per job.** `java-tests` in the same workflow file, still pinned, ran and passed.
- **The merge was blocked.** `script-tests` is a required check, and GitHub reported the PR's merge state
  as `BLOCKED`.
- **Semgrep saw it too.** The Code scan run on that PR (43587570482) stayed green, because the scan only
  reports until step 4, but it listed 2 findings instead of 1: the new one is
  `github-actions-mutable-action-tag` at `.github/workflows/ci.yml:28`.

PR #6 was closed without merging and the branch was deleted.

### Scorecard after steps 1 and 2

Scorecard v5.6.0 again (release binary downloaded again and checked against `scorecard_checksums.txt`,
Linux), run on 2026-11-14 against `main`
@ `8a27800`. Overall score: 3.8 to 4.6. Two checks changed:

| Check | Baseline (2026-11-12) | Now | Scorecard's reason |
|---|---|---|---|
| Pinned-Dependencies | 0 | 10 | 13 of 13 actions, 3 of 3 container images, 1 of 1 pip command pinned |
| Branch-Protection | 0 | 4 | "branch protection is not maximal" |

- **Branch-Protection stops at 4 by design.** Scorecard credits the PR requirement, the status checks, the
  up-to-date rule, blocked force pushes and deletion, and that the rules apply to administrators. Its
  warnings are all about reviews: no required approvers, no stale review dismissal, no code owner
  review, no last-push approval. A repo with one maintainer cannot approve its own PRs, so required
  approvals were left out on purpose.
- **Unchanged at 10:** Binary-Artifacts, CI-Tests (5 of 5 merged PRs), Dangerous-Workflow,
  Token-Permissions, Vulnerabilities.
- **Unchanged at 0:** Dependency-Update-Tool (step 3), SAST (0 of 8 commits), Code-Review (0 of 25
  changesets), License, Security-Policy, Maintained, CII-Best-Practices, Contributors, Fuzzing.
  Packaging and Signed-Releases are still not scored.

### What pinning does not cover

- **Three scanner images are not updated automatically.** Dependabot does not read image references held
  in a workflow `env:` value or in a shell script. That is the Trivy digest (`baseline-scan.yml`,
  `hardened-scan.yml`, `scripts/code-scan.sh`), the Semgrep digest (`scripts/code-scan.sh`) and the gitleaks
  digest (`scripts/history-scan.sh`). For now they are checked by hand: last checked 2026-11-13 (Trivy
  0.76.2 and gitleaks v8.30.1 are the latest releases; Semgrep is at 1.184.0, 1.185.0 exists). The Trivy
  digest must be the same in all three files.
- **The runner label** is not updated by Dependabot. `ubuntu-24.04` is what `ubuntu-latest` resolved to in
  the last run on `main` (2026-11-12), so the pin keeps the same image family. Moving to a newer image is a
  manual edit.
- **The Maven download is usually not re-checked in CI.** `setup-java` caches the wrapper's Maven
  distribution, and the wrapper checks the SHA-256 only when it downloads. CI trusts the Actions cache here.
- **Not pinned by hash:** Semgrep registry rule packs (fetched at scan time), the Trivy databases, Maven
  dependencies (fixed by version), the JDK that `setup-java` installs, and the Python patch version
  (`python-version: "3.12"`).
- **A pinned base image stops receiving patches** until its digest is updated. Step 3 is planned to add the update PRs.

## Step 3: Dependabot

Added on 2026-11-15 on the branch `phase4/step3-dependabot`: `.github/dependabot.yml`. This section
records the configuration and the rules for reviewing its pull requests. Dependabot reads the file from
the default branch (`main`), so nothing here has run yet. The results of the first run will be added
after the merge.

### Configuration

All four entries run weekly (Monday 09:00, Asia/Tbilisi) with a cooldown of 7 days: a new release should
only be proposed once it is 7 days old. The cooldown applies to version updates, not to security
updates.

| Ecosystem | Directory | Covers | Group | Ignored |
|---|---|---|---|---|
| `github-actions` | `/` | 13 `uses:` of 4 actions in 4 workflow files | `actions`, minor and patch only | - |
| `maven` | `/` | `pom.xml` (the Spring Boot parent) and, per the source, `.mvn/wrapper/maven-wrapper.properties` (Maven 3.9.16, wrapper 3.3.4) | none | major versions of Spring Boot and of Maven itself |
| `docker` | `/` | `Dockerfile`, `Dockerfile.hardened` (3 images) | `base-images` | `openjdk` completely; major versions of `eclipse-temurin`; every `maven` tag above the current one (see "Finding: the JDK hides in the tag") |
| `uv` | `/tests` | `requirements.in`, `requirements.txt` (6 packages) | `test-tools` | - |

- **Majors of actions should arrive one per PR.** A major version of an action can change its behaviour,
  so each one should be reviewed, merged or rejected alone. Minor and patch updates should share one PR.
- **No group for Maven.** At most three versions: the parent in `pom.xml` and the two in the wrapper
  properties.
- **The baseline image is excluded.** `Dockerfile` is the "before" evidence, so `openjdk` is ignored.
- **Java 17 and Maven 3 stay.** A new major of the JDK, of Spring Boot or of Maven is a migration that
  is planned, not an update PR.
- **`uv`, not `pip`.** `tests/requirements.txt` is compiled with `uv pip compile`, and the `uv` updater
  runs `uv pip compile` again with options read from the compiled file.

### What Dependabot is expected to do with the pins

Read from Dependabot's source (`dependabot/dependabot-core`, `main` @ `13987a8`, 2026-11-14). None of
this has been seen on a real pull request yet.

- **Actions pinned by SHA:** the SHA and the version comment on the same line are rewritten together.
- **`FROM` lines with a digest:** when a newer tag is chosen, tag and digest are rewritten together.
  When the tag stays the same, only the digest can be refreshed.
- **Hashed requirements:** the updater takes `--generate-hashes`, `--universal` and `--python-version`
  from the compiled file and keeps its header. `--only-binary :all:` is only on the install command in
  `ci.yml`, not in the compiled file, so the updater resolves without it. If an update had no wheel, the
  hashed install in `script-tests` would fail on the PR.

### Limits found in the plan review

- **The runtime image can only get digest refreshes.** For `eclipse-temurin:17-jre` the tag is not
  expected to change (the major is ignored), and the source contains a switch that suppresses
  digest-only updates for version-like tags. It is not known whether that switch is on for github.com.
  Until a digest-only PR has been seen, the two digests in `Dockerfile.hardened` are checked by hand
  like the scanner images. Last checked 2026-11-14: `eclipse-temurin:17-jre` still resolved to the
  pinned digest.
- **Ignore rules filter tags, not digests.** In the source, ignore rules with versions are applied to
  candidate tags only; an ignore without versions, like the one for `openjdk`, drops the dependency
  before the check (seen in the first run, below). The `17.0.2` tag is not expected to be rebuilt (not
  verified), but the rule is: a Dependabot PR that touches `Dockerfile` is closed, not merged.
- **A Maven wrapper update would replace a verified checksum.** If Dependabot updates
  `maven-wrapper.properties`, it writes the SHA-256 of its own download. The current value was derived
  from a download checked against Apache's `.sha512`. Before such a PR is merged, the sum is checked
  against Apache's `.sha512` again and the comment in the file is restored if the update dropped it.
- **Alerts are expected to miss transitive dependencies.** `pom.xml` declares the parent with a version,
  and two starters and one plugin without. Tomcat and Jackson, where the earlier findings were, are not
  declared in it. The repository setting "Automatic dependency submission" will be turned on together
  with the alerts. Whether it puts the resolved list into the dependency graph for this repo is not
  verified yet, see below.
- **Still not updated by Dependabot:** the Trivy, Semgrep and gitleaks image references and the runner
  label, as listed under "What pinning does not cover".

### Review rules for Dependabot pull requests

- The three required checks must be green, as for any PR.
- **`actions` and `base-images` PRs:** the Baseline and Hardened image scans are dispatched on the PR
  branch before merging. Both workflows use the same actions and Dockerfiles but do not run on pull
  requests.
- **Actions:** every new SHA is compared with `git ls-remote --tags` for the tag named in the comment
  (for an annotated tag, the peeled `^{}` line).
- With the up-to-date rule on `main`, the remaining PRs must be brought up to date after each merge.
  Dependabot did this by itself for PRs #11 and #13. For PR #10 a `@dependabot rebase` comment did
  nothing, and after a `@dependabot recreate` comment (17:06 UTC on 2026-11-15) Dependabot pushed a new
  commit at 17:25 UTC.

### How it will be checked after the merge

The pull request that adds the file cannot prove anything: no CI job parses `dependabot.yml`. The
checks below are the ones that can fail.

- The Dependabot page of the repository shows no configuration error and lists four ecosystems.
- The log of each first job matches the "Covers" column above.
- At least one real PR is reviewed with the rules above. On 2026-11-14 newer majors existed for
  checkout, setup-python and setup-java. setup-java v6.3.0 was published that day, so a PR opened within
  7 days must not propose it.
- The dependency graph lists `tomcat-embed-core` 11.0.27 and `pytest` 9.2.0.
- Scorecard's Dependency-Update-Tool is measured again. It is a metric, not proof that updates work.

### First run (2026-11-15)

The file was merged on 2026-11-15 as `82fd46e` (PR #8). Dependabot's first jobs started at 10:53 UTC,
one per ecosystem, and all four succeeded. Requiring SHA-pinned actions did not get in their way.

| Ecosystem | Job log | Result |
|---|---|---|
| `github-actions` | checked the 4 actions; `upload-artifact` 7.0.2 is the latest | PR #10 checkout 5.1.0 to 7.0.1, PR #11 setup-python 6.3.0 to 7.1.0, PR #13 setup-java 5.7.0 to 6.2.0 |
| `maven` | checked the parent (4.1.2), two starters and the plugin (no versions of their own), the wrapper (3.3.4, latest) and Maven itself | PR #12 apache-maven 3.9.16 to 3.10.0, in `maven-wrapper.properties` |
| `docker` | `openjdk`: "All versions of openjdk ignored, no update allowed"; `maven`: see the finding below; `eclipse-temurin 17-jre`: "Skipping tag 17-jre due to cooldown period" | PR #9, closed without merging |
| `uv` | checked `pytest` 9.2.0 only | no PR |

- **Majors arrived one per PR**, as configured.
- **The cooldown held, by falling back.** setup-java v6.3.0 was published on 2026-11-14, so Dependabot
  proposed v6.2.0 ("Found acceptable version outside cooldown: 6.2.0") instead of skipping the update.
- **The baseline image was skipped completely in this run.** The log shows "All versions of openjdk
  ignored, no update allowed" and no check of `openjdk`, so its digest was not compared either. The rule
  that a Dependabot PR touching `Dockerfile` is closed stays.
- **The runtime image digest was not checked for a refresh.** The `17-jre` tag was pushed again on
  2026-11-12, inside the 7-day cooldown. This is a second way the digest refresh can be held back,
  besides the suppression switch under "Limits found in the plan review": a tag pushed again more often
  than every 7 days never leaves the cooldown. The two digests in `Dockerfile.hardened` stay on the
  manual check list.
- **Only direct Python dependencies are checked.** The job looked at `pytest`, not at the 5 packages it
  pulls in. They are not checked by version updates; they can change when a `pytest` update recompiles
  the file, or through a security update.
- **The dependency graph holds the resolved Maven dependencies.** After Dependabot alerts, security
  updates and "Automatic dependency submission" were turned on (its runs succeed), the dependency graph
  (checked through the API on 2026-11-15) listed 83 packages, including `tomcat-embed-core` 11.0.27,
  `jackson-databind` 3.1.7 and `pytest` 9.2.0. Alerts are built from this graph; with 0 open alerts,
  none has been seen on a transitive dependency yet.
- The docker log also contains `UNAUTHORIZED` responses from Docker Hub. They are the first step of
  the anonymous login to the registry, and the job continued and succeeded.

### Finding: the JDK hides in the tag

PR #9 proposed `maven:3.9-eclipse-temurin-17` to `maven:3.9-eclipse-temurin-26`, which changes the
JDK of the build stage from 17 to 26. The ignore rule "no new major of `maven`" did not stop it.

Why, read from Dependabot's source (`dependabot-core`, `main` @ `13987a8`,
`docker/lib/dependabot/docker/tag.rb` and `version.rb`):

- For a tag like `3.9-eclipse-temurin-17`, the words are dropped and the numbers kept, so the tag is
  read as version 3.9.17. The JDK becomes the last number.
- `3.9-eclipse-temurin-26` is then 3.9.26: a patch update of 3.9.17, not a new major.
- GitHub's documentation says `ignore` version ranges for Docker use Bundler syntax and that
  `update-types` assumes `major.minor.patch`. Neither knows that the last number is a JDK.

Why the JDK 26 tag won over the newer Maven 3.10 tags: the job log treated every
`3.10-eclipse-temurin-N` tag as a pre-release ("The `latest` tag needs to point to
`3.10-eclipse-temurin-17` for Dependabot to consider it."). On Docker Hub, `maven:latest` had the same
digest as `3.10.0`, and 3.10.17 is above 3.10.0. As long as `latest` points to a Maven version below
3.10.17 (today 3.10.0), Dependabot treats these tags as pre-releases and does not propose them.

The fix replaces the `maven` rule with one version range:

```yaml
      - dependency-name: maven
        versions: [">= 3.9.17.1"]
```

- **Every tag above the current one is ignored.** That covers other JDKs on Maven 3.9, all Maven 3.10
  tags, the shorter `3-eclipse-temurin-N` tags (read as 3.N), and longer tags such as a future
  `3.9.17-eclipse-temurin-26` (read as 3.9.17.26). The lower bound is 3.9.17.1, not 3.9.18, because of
  those longer tags.
- **The current tag can still get digest refreshes.** 3.9.17 is outside the range. In the source, ignore
  rules only filter candidate tags, and with no candidate left the checker keeps the current tag
  (`update_checker.rb`, `select_best_candidate`) and then compares its digest. Maven patch releases
  under the `3.9` tag are expected to arrive this way. Not seen yet: the cooldown and the suppression
  switch can still hold them back.
- **Maven minor moves are made by hand.** The move to `3.10-eclipse-temurin-17` will go together with
  the wrapper update (PR #12), so that CI and the image build use the same Maven. The same pull request
  will raise the bound to `>= 3.10.17.1`.

A four-range version that would also have allowed `3.10-eclipse-temurin-17` was considered. Because of
the pre-release rule above, Dependabot would not propose that tag until `latest` moves past 3.10.17, so
the single range was kept.

How it was checked before the change: a small script that copies Dependabot's tag parsing and ignore
filter was run over the 548 `maven` tags whose name contains `eclipse-temurin` (Docker Hub API,
2026-11-15), plus two made-up future tags. With the old rule, 35 tags besides `3.9-eclipse-temurin-17`
passed the filter. With the new one, only the current tag remains, and both made-up tags are ignored.
The script does not model the cooldown, the pre-release rule or every precision rule, so the real check
is the next Dependabot run: it must not propose any `maven` tag. That run is described in the next
section.

### After the fix

PR #14 was merged on 2026-11-15 as `c4aa762`. The docker job that followed (Dependabot job 1705805515,
16:23 UTC) opened no pull request; its log ends with "No update needed" for both `maven` and
`eclipse-temurin`.

- **The range is what stopped the update.** The job received exactly three ignore conditions, all from
  `.github/dependabot.yml`: the `eclipse-temurin` major rule, `maven` `>= 3.9.17.1`, and `openjdk`
  `>= 0`. Closing PR #9 did not add an ignore condition of its own.
- **Two filters ran.** Every `3.10-eclipse-temurin-N` and `3.10.0-eclipse-temurin-N` tag, and every
  `3-eclipse-temurin-N` tag except `-8` (read as 3.8, below our 3.9.17), was rejected as a pre-release.
  The `3.9-eclipse-temurin-19` to `-26` tags (3.9.19 to 3.9.26) are not pre-releases (3.9.x is below
  3.10.0), so only the range could remove them. The log does not list ignored tags one by one; it shows
  the result, "Latest version is 3.9-eclipse-temurin-17" and "No update needed". Under the old rule the
  same tags produced PR #9. A `3.9-eclipse-temurin-27` tag does not exist on Docker Hub (list of
  2026-11-15).
- **An ignore without versions is sent as `>= 0`.** That is why `openjdk` is logged as "All versions of
  openjdk ignored" and not checked at all.
- **The runtime image was held by the cooldown again** ("Skipping tag 17-jre due to cooldown period").

The weekly run on Monday 2026-11-16 (05:40 UTC) opened no pull request. All four jobs succeeded:

- `docker`: `maven` and `eclipse-temurin` unchanged (`openjdk` skipped), `17-jre` still inside the
  cooldown.
- `github-actions`: no update for any of the four actions. setup-java v6.3.0 (2026-11-14) is still
  inside the cooldown, so the job again settled on v6.2.0.
- `maven`: Maven 3.10.0 is still proposed in PR #12, which is open (see below). Maven 3.10.1 is already
  published (on Maven Central since 2026-11-11) and was filtered out by the cooldown.
- `uv`: `pytest` 9.2.0 is current.

### Action updates: PRs #10, #11 and #13

The three major updates from the first run were reviewed with the rules above and merged on 2026-11-15.

| PR | Update | New SHA = tag | Workflows | Merged as |
|---|---|---|---|---|
| #10 | `actions/checkout` v5.1.0 to v7.0.1 | `3d3c42e5...` | all 4 (5 uses) | `6e3d5dd` |
| #11 | `actions/setup-python` v6.3.0 to v7.1.0 | `6d4fd22b...` | `ci.yml` (`script-tests`) | `114f739` |
| #13 | `actions/setup-java` v5.7.0 to v6.2.0 | `77dd5b2c...` | all 4 | `2e6ae91` |

- **SHA against the tag:** for each PR, `git ls-remote --tags` returned the PR's SHA for the new tag. All
  three are lightweight tags, so there was no `^{}` line to compare.
- **Signed and in the action's history:** each commit has a verified signature, and the GitHub compare API
  showed it as part of the action's `main` branch.
- **Runtime:** all three actions use `node24`, before and after.
- **Image scans:** for #10 and #13, Baseline and Hardened were dispatched on the PR branch before the
  merge (#10 on `fad960c`: runs 43741415709 and 43741425397; #13 on `8434bfb`: runs 43743009297 and
  43743014465). #11 changes only `ci.yml`, whose jobs ran on the PR.
- **Image results did not change.** The hardened image had 61 findings (0 C / 0 H / 56 M / 4 L /
  1 UNKNOWN) and the baseline image 381, before the updates (`c4aa762`), on both PR branches and on `main`
  after the last merge (`2e6ae91`).

What the release notes changed, and what that means here:

- **checkout v6 and v7.** Since v6, `persist-credentials` stores the token in a separate file under
  `$RUNNER_TEMP`, not in `.git/config`. Our `code-scan.yml` already sets `persist-credentials: false`;
  the other four checkouts still keep the token (step 5). v7 refuses to check out fork pull request code
  for `pull_request_target` and `workflow_run`, triggers we do not use. v5.1.0 itself was released on
  2026-07-20, the same day as v7.0.1.
- **setup-python v7.** The internals moved to ESM, and the `pip-install` input was removed. We pass only
  `python-version` and install with our own hashed `pip install`.
- **setup-java v6.** The internals moved to ESM, and legacy AdoptOpenJDK distributions were removed (we
  use `temurin`). JDK downloads now verify checksums, and signature verification is on by default for
  the distributions that support it. In our runs the JDK (17.0.21+9) came from the runner's tool cache,
  so no JDK was downloaded and the new download verification had nothing to check.

### Maven Central rate limit (HTTP 429)

The first Baseline run for PR #13 (run 43743009297, attempt 1) failed in "Build JAR": Maven could not
resolve `spring-boot-starter-parent:pom:4.1.2` ("present, but unavailable") because Maven Central
answered with status code 429, too many requests. The second attempt passed.

setup-java v6 did not cause it:

- With v5.7.0 and with v6.2.0, the JDK came from the runner's tool cache and the same Maven and wrapper
  cache keys were restored, so the dependencies were not downloaded again.
- The Maven builds checked log lines of the form "Artifact ... is present in the local repository, but
  cached from a remote repository ID that is unavailable in current build context, verifying that is
  downloadable from [central ...]". The Baseline runs with v5.7.0 (`114f739`) and v6.2.0 (`2e6ae91`) and
  the Code scan run on `2e6ae91` each logged 874 of them; the CI run on `2e6ae91` logged 904.

So each of these builds made 874 (CI: 904) re-checks against Maven Central, and one of those requests
was refused. Why the cached artifacts carry a repository ID the build does not know is not found yet. It
is on the step 5 list, together with the question of whether Maven 3.10's new resolver changes the
count.

### PR #12: Maven 3.10.0 for the wrapper

PR #12 changes the wrapper's Maven from 3.9.16 to 3.10.0. Its checksum was verified on 2026-11-16:

- The SHA-256 of `apache-maven-3.10.0-bin.zip` downloaded from Maven Central equals the PR's
  `distributionSha256Sum` (`1f6d9909...`).
- The zip's SHA-512 equals the `.sha512` file Apache publishes on downloads.apache.org and
  archive.apache.org, and the one on Maven Central.
- `gpg --verify` of Apache's `.asc`, with a throwaway keyring imported from Apache Maven's `KEYS` file,
  reported a good signature from key `88BE34F94BDB2B5357044E2E3A387D43964143E3`. The key is not
  certified in a web of trust, so this proves the zip was signed by a key Apache publishes, not more.

The PR is not merged as it is. It removes the two comment lines in `maven-wrapper.properties` that say
where the checksum comes from, and it stores `mvnw.cmd` in the repository with Windows line endings
(CRLF). Our `.gitattributes` (`*.cmd text eol=crlf`) keeps that file with LF in the repository and
converts it to CRLF only on checkout. The content of `mvnw.cmd` is otherwise unchanged. The move to
Maven 3.10 will be its own pull request, planned for 2026-11-19 or later. Because Maven 3.10.1 leaves
the cooldown on 2026-11-18, the version is chosen on that day, and the checksum and signature checks
above are repeated for the zip actually used. The pull request changes:

- the wrapper's `distributionUrl` and `distributionSha256Sum`, with both comment lines kept;
- the build stage of `Dockerfile.hardened` on `maven:3.10-eclipse-temurin-17`, pinned to a digest that
  is at least 7 days old;
- the `maven` bound in `dependabot.yml` raised to `>= 3.10.17.1`.

The raised bound carries more weight than the old one. After the move, the current tag reads as 3.10.17,
which is above `maven:latest` (3.10.0 on 2026-11-15; still above it if `latest` moves to 3.10.1), so
Dependabot treats our own tag as a pre-release. In that case its source keeps pre-release candidates
instead of removing them (`remove_prereleases` in `update_checker.rb`), so `3.10-eclipse-temurin-21` and
similar tags become candidates again. The bound is the only rule meant to stop them.

## Step 4: security gates

Until this step every scan only reported. Step 4 made findings block merges, in three pull requests,
each proven with its own red test before the next one started:

| PR | Merged | Gate | Job (required check) |
|---|---|---|---|
| #16 | 2026-11-16 as `d3c9fac` | Trivy on the repo and `app.jar`, Semgrep on new code, `.trivyignore` | `scan` (already required) |
| #19 | 2026-11-16 as `cffd947` | gitleaks over the full git history | `secrets` (new) |
| #21 | 2026-11-17 as `57e7f87` | Trivy on the hardened image, retries, daily schedules | `compare` (now on pull requests) |

### Exit codes

Every gate script uses the same two exit codes, so a red check says what kind of problem it is:

- **10: a security finding.** Each gate script exits 10 in exactly one place, at the end, after all its
  checks have run. The job log shows an error annotation titled "Security gate". A run that failed with
  10 is never rerun to get past it; the finding has to be fixed or accepted.
- **1: a tool or network error.** Any other failure (a scanner, Docker, git, a build or a download) ends
  with 1: in the scripts through an exit trap, in the separate build and download steps through the step
  itself. These runs may be rerun.

The three scripts are `scripts/code-scan.sh` (job `scan`), `scripts/history-scan.sh` (job `secrets`) and
`scripts/image-gate.sh` (job `compare`).

### The gates

| Gate | Fails on | Does not fail on |
|---|---|---|
| Trivy, repo (`pom.xml`, `tests/requirements.txt`) and `app.jar` | any CRITICAL or HIGH finding; any secret Trivy reports in the repository scan | MEDIUM, LOW, UNKNOWN |
| Semgrep | ERROR findings that are new since the base commit | existing findings, such as `missing-user-entrypoint` at `Dockerfile:23`; WARNING findings |
| gitleaks | any leak in the full history (`--all`) | |
| Trivy, hardened image | CRITICAL findings that have a fixed version | HIGH and below; CRITICAL without a fix |
| Trivy, baseline image | nothing: report-only, it is the "before" evidence | |

- **Base commit for Semgrep.** On a pull request it is the first parent of the merge commit GitHub
  builds, which is the tip of `main`. On a push to `main` it is the previous `main`. Semgrep needs a
  writable repository for this, so it runs on a throwaway clone; the real checkout stays read-only.
  The canary files are left out of this scan, and `# nosemgrep` comments are ignored, so a finding
  cannot be waived inside the code.
- **Accepted risks.** The Trivy gates read `.trivyignore`. `code-scan.sh` checks the file before any
  scan: each entry must be a `CVE-` or `GHSA-` ID with a review date (`exp:`) at most 90 days ahead, and
  a `# reason:` line directly above it. Once the date passes, Trivy reports the finding again. The file
  has no entries today.
- **Before the gitleaks scan**, the script builds a small repository with a fake key and checks that
  gitleaks finds it and redacts it. On `main` the job's report files are owned by the runner user
  (UID 1001), which shows the scanner container did not run as root.

### Red tests

Each gate was made to fail on purpose: in this repository with a pull request that was closed without
merging, and for the fake key in a separate private repository.

| Test | Change | Run | Result |
|---|---|---|---|
| PR #17 | `log4j-core` 2.14.1 in `pom.xml` | `scan` 43896648689 | exit 10: CVE-2021-44228 and CVE-2021-45046 (CRITICAL), CVE-2021-45105 (HIGH), each in `pom.xml` and in the JAR; Semgrep gate 0; BLOCKED |
| PR #18 | `management.endpoints.web.exposure.include=*` in `application.properties` | `scan` 43898710709 | exit 10: exactly one new ERROR, `spring-actuator-fully-enabled` at `application.properties:4`; `Dockerfile:23` not in the gate; Trivy 0; BLOCKED |
| Private throwaway repository | a fake AWS key in its own commit | `secrets` 43910012093, 43913780930 | first run green; second run exit 10, `aws-access-token` at `config.ini:1` |
| PR #20 | a trailing space in `LOG_OPTS` | `secrets` 43920595979 | exit 1, a tool error from git; the only red check; BLOCKED once `secrets` was required |
| PR #22 | `log4j-core` 2.14.1 in `pom.xml` | `compare` 44163890985, `scan` 44163891124 | `compare` exit 10: canary ok, CVE-2021-44228 and CVE-2021-45046 in `app.jar`; `scan` exit 10 as in #17 |
| PR #23 | the image gate reads a scan file that does not exist | `compare` 44164002985 | exit 1 ("missing"); the only red check; BLOCKED |

- **The fake key test ran in a separate private repository**, because anything pushed to this public
  repository stays retrievable by its commit SHA. GitHub's push protection did not block the fake key
  there. The key appears nowhere in the run logs or in any of the three artifact files; the report shows
  it as `REDACTED`. The repository was deleted afterwards.
- **PRs #20 and #23 test the ruleset, not the scanner.** A tool error is enough to make the job red, and
  when that job is the only red check, a BLOCKED pull request shows that the ruleset enforces it.
- **Local tests** before each pull request covered the cases that are awkward to push: every
  `.trivyignore` lint error (exit 1), an accepted CVE turning a gate green and an expired one turning it
  red again, an invalid base commit (exit 1), and `GATE=0`, which reports findings without failing.

### Finding: a new job blocks nothing until it is in the ruleset

`secrets` was merged in PR #19, but a required check is a name in the ruleset, not a property of the
job. Before `secrets` was added to the ruleset by hand, a red `secrets` run did not block PR #20 (seen
on the pull request page; GitHub keeps no record of it); after the addition (2026-11-16, 18:11 UTC), the
same PR showed BLOCKED. `compare` was added the same way on 2026-11-17, after its first green run on
`main` with the gate (44162204650).

The routine for every new gate job:

1. Merge the job.
2. Wait for one green run on `main`.
3. Add the exact job name to the ruleset `protect-main`.
4. Prove it with a red pull request in which that job is the only red check.

Required checks now: `java-tests`, `script-tests`, `scan`, `secrets`, `compare`. This replaces the three
listed under step 1, written when `compare` did not yet run on pull requests.

### The image gate's canary, and what "0" means

A scan that never looked inside the application JAR would also report zero findings. Before the image
gate runs, it checks that the full scan of the hardened image lists `tomcat-embed-core`, a library that
only our JAR brings. Run against a scan of the bare base image, which has no JAR, the check failed with
exit 1 (local test, 2026-11-17).

"The gate passed" is not "no findings". On `main` after PR #21 the hardened image still has 61 findings
(0 CRITICAL, 0 HIGH, 56 MEDIUM, 4 LOW, 1 UNKNOWN), all in the base image. The gate passes because none of
them is a CRITICAL with a fix. The baseline image has 381 findings and is not gated.

### Why downloads and builds retry

On 2026-11-17 the vulnerability database download failed four times in a row on this PC, each time with
`context deadline exceeded` from `mirror.gcr.io`, although Trivy also lists `ghcr.io` as a fallback. In
CI the same failure would stop the image gate. So `compare` downloads both databases in a step of its
own, with three tries 30 and 60 seconds apart, and every scan after it runs with `--skip-db-update`. The
JAR builds (`code-scan.yml`, `baseline-scan.yml`, `hardened-scan.yml`) and the image builds retry once
after 60 seconds, because of the Maven Central 429 seen in step 3; `ci.yml`'s `./mvnw verify` does not,
so `java-tests` can still turn red on a 429. In `compare`, a red download or build step is an
infrastructure problem; only a red gate step with exit 10 is a security result. In `scan` and `secrets`
the scan and the gate share one step, and `scan` downloads the Trivy databases inside it without a retry
loop, so there the exit code (10 or 1) is what tells them apart.

### Known limits

- **Any pull request can accept its own risk.** A change can add an entry to `.trivyignore` together with
  the vulnerable dependency. The lint only forces a reason and a review date. In a team, a `CODEOWNERS`
  entry for `.trivyignore` with required review would close this; with one maintainer, the review date
  is the only control.
- **Daily schedules can stop.** `code-scan.yml` (04:23 UTC) and `hardened-scan.yml` (04:37 UTC) now also
  run every day on `main`, so a newly published CVE that meets a gate turns `main` red without any
  commit. GitHub disables scheduled workflows in a public repository after 60 days without repository
  activity. They run on `main` only, and a red scheduled run blocks nothing by itself.
- **A tool error hides a gate result.** If a gate script fails with 1, the gates that already ran are
  not reported as a security failure. The rerun shows them.
- **The Semgrep gate sees committed changes only.** On a scheduled run, base and head are the same commit,
  so the Semgrep gate has nothing to compare and is skipped; the Trivy gates still run.
- **Trivy's secret check is a second net.** In a local trial (2026-11-16), Trivy reported no secret in a
  file holding the same fake AWS key that gitleaks finds. The `secrets` job is the gate for secrets.

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

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
  branch).

Scorecard's Branch-Protection score will be measured again with the other checks at the end of the phase.

# Phase 4: CI/CD security

**Goal:** make the pipeline itself hard to tamper with: protected main branch, every action and image pinned
by SHA or digest, automated update PRs, and scans that can fail a build.
**Status:** in progress. This file starts with the "before" numbers; each step adds its "after".

## Baseline

Measured on 2026-11-12 against `main` @ `748436f`, before any Phase 4 change. Both tools only read.

| Tool | Version | Looks at | How it was run |
|---|---|---|---|
| OpenSSF Scorecard | v5.6.0 (release binary, SHA256 checked against `scorecard_checksums.txt`) | The GitHub repo: settings, workflows, history | `scorecard --repo=github.com/nikalolo/secure-java-api --format json --show-details` on Linux (WSL) |
| zizmor | 1.32.0 (PyPI) | `.github/workflows/*.yml` | `zizmor --format json .github/workflows`, with a GitHub token (online audits) and with `--offline` |

### Scorecard: 3.8 / 10

Scorecard gives each check 0-10; `?` means Scorecard could not score the check (nothing to evaluate yet).

| Check | Score | Reason reported | Phase 4 |
|---|---|---|---|
| Binary-Artifacts | 10 | no binaries in the repo | - |
| CI-Tests | 10 | 4 of 4 merged PRs checked by CI | - |
| Dangerous-Workflow | 10 | no dangerous workflow patterns | - |
| Token-Permissions | 10 | all 4 workflows set top-level `contents: read`, no job-level write | already done in Phases 1-3 |
| Vulnerabilities | 10 | 0 open vulnerabilities | - |
| Branch-Protection | 0 | branch protection not enabled on `main` | step 1 |
| Pinned-Dependencies | 0 | 0 of 13 actions, 0 of 3 Dockerfile base images, 0 of 1 `pip install` pinned by hash | step 2 |
| Dependency-Update-Tool | 0 | no update tool detected | Dependabot |
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

### zizmor: 17 findings

| Audit | Severity | Count | Where |
|---|---|---|---|
| `unpinned-uses` | High | 13 | every `uses:` in the 4 workflows (tags like `@v5`) |
| `artipacked` | Medium | 4 | checkouts without `persist-credentials: false`: `ci.yml` (2), `baseline-scan.yml`, `hardened-scan.yml` |

Same 17 online and offline. The pedantic persona adds 9 lower ones (26 total): `concurrency-limits` (Low, 4)
and `anonymous-definition` (Informational, 5).

### Semgrep (from Phase 3, 2026-11-11)

Not re-run for this baseline: the workflows have not changed since.

| Rule | Count | Where |
|---|---|---|
| `github-actions-mutable-action-tag` | 13 | the same 13 `uses:` lines |
| custom rule: Docker image without `@sha256` in workflow and shell files | 3 | `aquasec/trivy:latest` in `baseline-scan.yml` (2) and `hardened-scan.yml` (1) |

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

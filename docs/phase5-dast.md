# Phase 5: DAST with OWASP ZAP

**Goal:** test the running container from the outside, fix what that finds, and turn the result into a check
that blocks merges.
**Status:** done (2026-11-24). Baseline, fix (PR #36), gate (PR #37), red test (PR #38). All times are UTC.

## Scope and safety

ZAP only ever scans our own container, locally and inside the CI runner, never an external URL.

- **No way out.** ZAP and the app share a Docker network created with `--internal`: no DNS and no route to
  the internet. The app is reachable only as `http://app:8080`. Every run proves this before the scan: curl
  to `https://github.com` must fail with code 6 (no DNS) and to `http://1.1.1.1` with code 7 (could not
  connect). Any other result, including success or a TLS error, stops the run.
- **Only the app under test.** Before ZAP starts, every URL in the scan plan must be `http://app:8080` or a
  path under it.
- **Pinned image, no downloads.** `zaproxy/zap-bare:2.17.0`, pinned by digest. ZAP runs with `-silent`
  (no update checks), and the network has no way out anyway.
- **Both containers locked down.** Read-only root filesystem, all Linux capabilities dropped,
  `no-new-privileges`, not privileged, not root, plus memory and process limits. The script reads the first
  five back with `docker inspect` and refuses to scan if one is missing; the limits are set but not read
  back.
- **Passive rules only in CI.** ZAP looks at the responses to a fixed list of requests. The active scan
  (attacks) was measured once and is not part of CI (see below).

## Tool choice

| | `zaproxy/zap-bare:2.17.0` (chosen) | `zaproxy/zap-stable:2.17.0` |
|---|---|---|
| Size | 1.2 GB | 3.75 GB |
| Trivy findings in the image (2026-11-22) | 35 (1 CRITICAL, 5 HIGH) | 4958 (22 CRITICAL, 627 HIGH) |
| Python wrapper `zap-baseline.py` | no | yes |
| How it runs here | Automation Framework plan: `zap.sh -cmd -silent -autorun plan.yaml` | `zap-baseline.py` |

Both images run as UID 1000 and ship the same 86 add-ons. `zap-baseline.py` first downloads add-on
updates unless it is called with `-z "-silent"`; the bare image has no wrapper to do that. ZAP 2.17.0 is
the latest stable release.

The Automation Framework's exit code says whether the plan ran, not what it found: 0 = ok, 1 = plan error,
2 = plan warnings. A run with a Low finding still exits 0. So the gate reads the JSON report itself.

## Baseline (2026-11-22, `main` @ `8de0b55`)

The hardened image ran with the same runtime flags as in CI.

**First run:** `zap-baseline.py` (stable image, `-silent`) with `/health` as the target: 61 rules passed,
1 warning, `10021` X-Content-Type-Options Header Missing (Low) on `/health`. The bare image with an
equivalent plan gave the same result.

A plain request showed why: every response carried only `Content-Type` (plus `Allow` on the 405), and
`GET /error` answered 500 with `"status":999`.

**The real baseline:** an independent review of the plan found that a ZAP context of `/health` hides other
paths. ZAP received the error responses but did not scan them. With the context set to `http://app:8080/`
and requests to `/does-not-exist`, `/error` and `POST /health`, the baseline was 2 Low findings:

| Rule | Risk | Where | Meaning |
|---|---|---|---|
| 10021 | Low | `/health` (the canary request) | no `X-Content-Type-Options: nosniff` |
| 90022 | Low | `/error` | Application Error Disclosure (the 500 error body) |
| 10024 | Informational | `/health?password=zapcanary` | the canary (see below), not a finding |

Status codes and headers before the fix (the gate's own checks, run on the pre-fix image on 2026-11-23):

| Request | Status | nosniff | X-Frame-Options DENY | no-store | CSP |
|---|---|---|---|---|---|
| `GET /health` | 200 | no | no | no | no |
| `POST /health` | 405 | no | no | no | no |
| `GET /does-not-exist` | 404 | no | no | no | no |
| `GET /error` | 500 | no | no | no | no |

## The fix: deny by default (PR #36, `41fa58f`)

There were two options: add the headers and keep 404/405, or deny everything except `GET /health`. The
owner chose deny by default on 2026-11-23.

- `spring-boot-starter-security` (Spring Security 7.1.2). `SecurityConfig` allows `GET /health` and answers
  every other request with 403. Sessions are stateless; HTTP Basic and form login are off. Spring
  Security's default headers (`nosniff`, `X-Frame-Options: DENY`, a `Cache-Control` with `no-store`) plus
  a Content-Security-Policy `default-src 'none'; frame-ancestors 'none'` go on every response,
  including the 403s.
- **CSRF protection is off, on purpose.** The API has no cookies, no sessions and allows only `GET`. Left on,
  CSRF made `POST /health` set a `JSESSIONID` cookie, which ZAP flags as `10054` (cookie without SameSite,
  Low). Semgrep reported nothing either way.
- `UserDetailsServiceAutoConfiguration` is excluded: the API has no users, and it created an unused
  in-memory user and logged its generated password at startup.
- 5 new jars in `app.jar` (the Spring Security 7.1.2 jars and `spring-boot-security` 4.1.2); Trivy on the
  JAR: 0 findings.

**Tests.** `@WebMvcTest` does not load `SecurityConfig` on its own: in the first prototype the existing
tests still passed with Spring Security added, without seeing any of it. The new `SecurityConfigTest`
imports it and checks 200/403/403/403 plus the 4 headers on each response. The old 405 and 404 tests moved
there as 403 tests; `HealthControllerTest` keeps only `GET /health` 200. Two mutation checks show the tests can fail:

- without `@Import(SecurityConfig.class)`, 4 of 4 fail (500/405/404 instead of 403);
- without the CSP line, 4 of 4 fail.

`spring-boot-starter-security-test` is not added: it turned the existing tests red through Spring's default
security chain. `./mvnw verify`: 5 tests, 0 failures, locally and in CI.

**After the fix (local, 2026-11-23):** `GET /health` 200, everything else 403, all 4 headers on all 4
responses. ZAP: only the canary.

**Side effect:** the naive baseline `Dockerfile` copies the same JAR, so the baseline image now serves the
same headers and 403s. The 405/404 results in the Phase 1-4 docs are dated records of the app before this
change.

## The gate: `dast` (PR #37, `75705f2`)

`.github/workflows/dast.yml`, job `dast`, runs on every pull request, on pushes to `main` and by hand. It
builds `Dockerfile.hardened` from the commit under test (one retry for Maven Central errors) and runs
[`scripts/dast-scan.sh`](../scripts/dast-scan.sh) on it. There is no daily schedule: the app and ZAP are
pinned, so the result only changes when the code does.

What one run does, in order:

1. Checks `.zap/accepted-risks` (format below) and the plan's URLs.
2. Creates the internal network, starts the app with the hardened flags, checks the app's runtime with
   `docker inspect`, and tries `GET /health` up to 60 times, 1 s apart.
3. Proves the network has no way out (curl codes 6 and 7, as above).
4. **Its own checks:** 4 requests, each with an expected status (`GET /health` 200, `POST /health`,
   `GET /does-not-exist` and `GET /error` 403) and 4 headers (`nosniff`, `X-Frame-Options: DENY`,
   `Cache-Control` with `no-store`, the exact CSP): 20 checks. ZAP's `10021` does not fire on 404/500
   responses even at threshold Low (tested in the review), so the script checks the error responses
   itself.
5. Runs ZAP with [`.zap/plan.yaml`](../.zap/plan.yaml): 5 requests (the 4 above and the canary), passive
   rules, a JSON report. ZAP's container is checked with `docker inspect` the same way as the app's.
6. Gates on the results, writes two tables to the job summary, and removes the containers and the network.

### Exit codes

| Exit | Meaning | Examples |
|---|---|---|
| 0 | gate passed | |
| 10 | security finding | a wrong status code (`POST /health` 200), a missing or wrong header, a ZAP alert rated Low or higher that is not accepted |
| 1 | tool or setup error | app never healthy, ZAP plan error, no report, canary missing, network not isolated, a container not locked down, plan URL outside the app, bad accepted-risks file |

All findings are printed first, then one exit 10 with a `Security gate` error annotation. A red `dast` with
exit 10 should not be rerun to get past it.

### The canary

A request to `GET /health?password=zapcanary` must make ZAP raise `10024` (sensitive information in the
URL, Informational). If it does not, ZAP did not really look at the traffic and the run exits 1. So "0
findings" only counts when the canary fired. The string is not a secret and needs no allowlist: gitleaks
found nothing in a test repo with the canary line (2026-11-23), and with the real plan the local Trivy
secret scan found 0 and the `secrets` and `scan` checks were green on PR #37.

### Accepted risks

`.zap/accepted-risks` works like `.trivyignore`. Each entry is a ZAP rule ID with a review date at most
90 days ahead and a `# reason:` line directly above it:

```
# reason: version banner comes from the proxy in front; remove when it is stripped
10036 exp:2026-12-31
```

An entry covers every URL the rule fires on (whole-rule waivers, the owner's decision). The file is checked
before any scan, and each of these exits 1: a malformed line, an invalid date, a date more than 90 days
ahead, a missing reason, the same rule twice. Once the date has passed, the alert counts again. An entry
that never fires is reported so it can be removed. The file starts empty: nothing is accepted today.

### Local failure tests (2026-11-23)

Each case ran a copy of the script in its own folder. Two throwaway images were built from the fixed image:
one sending `Server: Apache/2.4.1`, one that never starts the app.

| Case | Exit |
|---|---|
| fixed image | 0 |
| pre-fix image (19 status/header failures, `10021`, `90022`) | 10 |
| `Server: Apache/2.4.1` (only `10036`) | 10 |
| same, `10036` accepted for 30 days | 0 |
| same, `10036` accepted until yesterday | 10 |
| accepted-risks: no reason / date 100 days ahead / invalid date / non-numeric ID / duplicate ID | 1 each |
| plan URL `http://example.com/` (stopped before any container started) | 1 |
| plan without the canary request | 1 |
| plan with an unknown job type | 1 |
| app never answers `/health` | 1 |
| image does not exist | 1 |
| network created without `--internal` (and the internal check removed from the copy) | 1, at the egress check: both curls succeeded |

16 of 16 matched. The first run showed 15 of 16 because of a folder-name mistake in the test harness, not in
the script; the case passed when rerun.

## CI results

| Run | Commit | Result |
|---|---|---|
| 45260141188 (PR #37) | `f2702d2` | green, job 59 s |
| 45261454066 (push to `main`) | `75705f2` | green |
| 45455078472 (red PR #38) | `b533240` | red, exit 10 |

In all three runs the log shows the app container as UID `10001:10001` and the ZAP container as
`1001:1001`, both read-only, all capabilities dropped, `no-new-privileges`, not privileged. On Linux the
script runs ZAP as the runner's user (`1001:1001` in the log) so it can write the report into the runner's
folder, and the report was written. That ZAP's default UID 1000 would fail there was not tested. Egress:
code 6 for `github.com`, code 7 for `1.1.1.1`. All 20 status/header checks (4 requests) passed.

GitHub masks `password=zapcanary` as `***` in the logs ("canary ok: 10024 on the *** request"). The cause
was not looked into.

## Gate routine and red test

1. PR #37 merged 2026-11-23 20:38; `dast` green on the push to `main` (run 45261454066).
2. The owner added `dast` to the ruleset `protect-main` (updated 20:41), which now requires 7 checks:
   `java-tests`, `script-tests`, `scan`, `secrets`, `compare`, `workflow-lint`, `dast`.
3. Red PR #38 added one setting (plus a two-line comment) to `application.properties`:
   `server.server-header=Apache/2.4.1`. Result: only
   `dast` red with exit 10, 0 status/header checks failed, `10036` "Server Leaks Version Information"
   (Low) on `/error`, `/health` and the canary URL. The other 6 required checks and `submit-maven` passed.
   The PR showed BLOCKED (seen by the owner) and was closed without merging on 2026-11-24.

Only `dast` caught it. `java-tests` uses MockMvc, which never starts Tomcat, so it never sees the `Server`
header. Semgrep does read `application.properties`, but no rule covers `server.server-header`, and Trivy
looks at dependencies. The URLs listed for `10036` vary between runs: 3 or 4 locally (sometimes also
`/does-not-exist`), 3 in CI. That was not looked into.

## Active scan: measured, not a gate

On 2026-11-22 an active scan (ZAP sends attack payloads) against the same context took 2 seconds. Before
the fix it added only `10104` User Agent Fuzzer (Informational); against the prototype of the fix (same
security config) it added nothing. With one
endpoint that takes no parameters, body or cookies, there is nothing to inject. It stays out of CI until
the API gets inputs or authentication.

## What DAST shows here, and what it does not

- **It shows** how the real container answers: status codes, security headers, the server banner, error
  details. It runs against the image that would ship, so it catches regressions that the unit tests and
  code scanners did not see (PR #38).
- **It does not show** authentication or authorization problems (there are none to test), injection (no
  inputs), TLS or HSTS (the app speaks plain HTTP; TLS would end in front of it), business logic,
  or anything ZAP's passive rules do not model. A green `dast` means "these rules found nothing in these 5
  responses", not "secure".
- **The findings were small.** Both baseline findings were also visible with `curl -i` on `/health` and
  `/error`. The value is
  the regression check on every PR.

## Known limits and open items

- **The ZAP image is checked by hand.** Dependabot does not update image references inside scripts. It is
  on the manual list in the [Phase 4 doc](phase4-cicd-security.md): last checked 2026-11-23, when `2.17.0`
  still pointed to the pinned digest (pushed 2026-11-03).
- **The ZAP image has its own vulnerabilities** (35, 1 CRITICAL and 5 HIGH, Trivy 2026-11-22). It runs
  locked down on a network with no way out, and it is not gated.
- **Image signature not verified.** On 2026-11-22 no cosign signature was found and the image was built
  with `provenance: false`; ZAP's release workflow used an action referenced by `@main` with secrets. On
  2026-11-23 Docker Hub also listed a tag `sha256-30b1344e...`, the naming used for signatures or
  attestations attached to an image. What it holds was not checked. Signing and provenance are Phase 7.
- **Whole-rule waivers.** An accepted rule covers every URL, so a future endpoint would inherit the waiver
  until its review date.
- **amd64 only.** The pinned ZAP image has no arm64 variant.
- **Not in Phase 5:** TLS and HSTS (not planned yet), authentication, an API scan driven by an OpenAPI spec (there
  is no spec yet), a scheduled ZAP run.

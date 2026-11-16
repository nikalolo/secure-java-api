#!/usr/bin/env bash
# Code scan: Semgrep (registry packs + custom rules) and Trivy (pom.xml, app.jar,
# secrets) via Docker. Requires: docker, jq, python, git, ~/.m2 and a fresh
# target/app.jar (./mvnw -B -ntp package -DskipTests).
# Exit 10: a security gate failed (trivy CRITICAL/HIGH or a secret in the repo
# or jar, or a new semgrep ERROR finding). Exit 1: a tool or setup error,
# including a silent canary. GATE=0 reports findings without gating.
set -euo pipefail

# 10 is reserved for the gate result at the end; any other failure leaves with 1
gate_exit=0
tmp=""
cleanup() {
  local rc=$?
  if [ -n "$tmp" ]; then rm -rf "$tmp"; fi
  if [ "$rc" -ne 0 ] && [ "$gate_exit" -eq 0 ]; then exit 1; fi
}
trap cleanup EXIT

cd "$(dirname "$0")/.."

# git bash rewrites /src-style args; docker desktop wants a D:/... mount path
export MSYS_NO_PATHCONV=1
SRC="$(pwd -W 2>/dev/null || pwd)"
OUT=scan-out
# digest-pinned: tags can be moved (aquasec/trivy, march 2026)
SEMGREP_IMAGE="semgrep/semgrep:1.184.0@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed"
# signature checked with cosign: aquasecurity/trivy reusable-release.yaml@refs/tags/v0.76.2
TRIVY_IMAGE="aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"
JAR=target/app.jar
REQUEST_MAPPING_RULE=java.spring.security.unrestricted-request-mapping.unrestricted-request-mapping
CANARY=.semgrep/canary/
# one rule per --config that only that config ships (p/java has none: all its
# rules are also in p/owasp-top-ten, so use-of-md5 proves the rule, not the pack)
CANARY_IDS=(
  java.lang.security.audit.crypto.use-of-md5.use-of-md5
  java.spring.security.audit.spring-actuator-fully-enabled.spring-actuator-fully-enabled
  yaml.github-actions.security.curl-eval.curl-eval
  "$REQUEST_MAPPING_RULE"
  docker-image-without-digest
  spring-error-details-exposed
)

command -v jq >/dev/null || { echo "jq not found on PATH" >&2; exit 1; }

die() { echo "$*" >&2; exit 1; }
build_hint="build it first: ./mvnw -B -ntp package -DskipTests"

# windows has a python3 store stub that is on PATH but doesn't run
PY=""
for candidate in python3 python; do
  if "$candidate" --version >/dev/null 2>&1; then PY=$candidate; break; fi
done
[ -n "$PY" ] || die "no working python3/python found"

# mtime says nothing after a checkout; check the jar holds the pom's boot version
[ -f "$JAR" ] || die "$JAR missing; $build_hint"
boot_version=$(sed -n '/<parent>/,/<\/parent>/s/.*<version>\(.*\)<\/version>.*/\1/p' pom.xml)
[ -n "$boot_version" ] || die "cannot read the spring boot parent version from pom.xml"
# no grep -q: it exits early and pipefail would then report unzip's SIGPIPE
if ! unzip -Z1 "$JAR" | grep -x "BOOT-INF/lib/spring-boot-$boot_version.jar" >/dev/null; then
  die "$JAR was not built from this pom.xml (spring boot $boot_version); $build_hint"
fi

# without ~/.m2, trivy fs either hits maven central (429s) or, offline,
# silently resolves nothing
M2="$HOME/.m2"
[ -d "$M2/repository" ] || die "$M2/repository missing; $build_hint"
M2_MOUNT="$(cygpath -w "$M2" 2>/dev/null || echo "$M2")"

# accepted risks for the trivy gates; every entry needs a reason and a
# review date, so nothing is waived silently or forever
IGNOREFILE=.trivyignore
echo "== $IGNOREFILE lint"
[ -f "$IGNOREFILE" ] || die "$IGNOREFILE missing (a file with only comments is fine)"
today=$(date -u +%F)
max_exp=$(date -u -d "+90 days" +%F)
entry_re='^(CVE-[0-9]{4}-[0-9]+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}) exp:([0-9]{4}-[0-9]{2}-[0-9]{2})$'
reason_re='^# reason: [^ ]'
prev="" n=0 entries=0 lint_failed=0
while IFS= read -r line || [ -n "$line" ]; do
  n=$((n + 1))
  line=${line%$'\r'}
  case "$line" in "" | "#"*) prev=$line; continue ;; esac
  entries=$((entries + 1))
  if [[ ! "$line" =~ $entry_re ]]; then
    echo "line $n: expected '<CVE-... or GHSA-...> exp:YYYY-MM-DD', got: $line" >&2
    lint_failed=1
  else
    exp=${BASH_REMATCH[2]}
    if ! date -u -d "$exp" +%F >/dev/null 2>&1; then
      echo "line $n: $exp is not a valid date" >&2
      lint_failed=1
    elif [[ "$exp" > "$max_exp" ]]; then
      echo "line $n: review date $exp is more than 90 days ahead (max $max_exp)" >&2
      lint_failed=1
    elif [[ ! "$exp" > "$today" ]]; then
      # not a lint error: trivy stops suppressing it, so the gate reports it
      echo "line $n: review date $exp has passed; the finding counts again"
    fi
  fi
  if [[ ! "$prev" =~ $reason_re ]]; then
    echo "line $n: needs a '# reason: ...' line directly above" >&2
    lint_failed=1
  fi
  prev=$line
done < "$IGNOREFILE"
[ "$lint_failed" -eq 0 ] || die "$IGNOREFILE lint failed"
echo "entries: $entries"

mkdir -p "$OUT"

# on linux ci, run as the runner user so output files aren't root-owned
docker_user=()
container_home=/root
trivy_cache=trivy-cache  # named volume, shared with the image scans
if [ "$(uname -s)" = Linux ]; then
  docker_user=(--user "$(id -u):$(id -g)" -e HOME=/tmp -e XDG_CACHE_HOME=/tmp/.cache)
  container_home=/tmp
  # a root-owned named volume isn't writable as the runner user
  trivy_cache="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"
  mkdir -p "$trivy_cache"
fi

# scanners get the repo read-only; they write only to the output mount
semgrep() {
  docker run --rm ${docker_user[@]+"${docker_user[@]}"} \
    -v "$SRC:/src:ro" -v "$SRC/$OUT:/out" -w /src \
    "$SEMGREP_IMAGE" semgrep "$@"
}

echo "== semgrep --test (custom rules vs their samples)"
semgrep --test --metrics=off .semgrep/rules/

echo "== semgrep scan"
# without --error, exit 0 means "ran", with or without findings.
# --quiet hides the reason for a non-zero exit, so print it from the json.
rm -f "$OUT/semgrep.json"
rc=0
semgrep scan --metrics=off --quiet \
  --config p/java --config p/owasp-top-ten --config p/github-actions \
  --config "r/$REQUEST_MAPPING_RULE" --config .semgrep/rules/ \
  --json --output /out/semgrep.json . || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "semgrep failed (exit $rc)" >&2
  if [ -s "$OUT/semgrep.json" ]; then
    jq -r '.errors[]? | "  \(.type // "error"): \(.message // .)"' "$OUT/semgrep.json" >&2
  fi
  exit "$rc"
fi

echo "== canary check"
# proves the real scan (same image, mount, ignore file) fires each rule set
missing=0
for id in "${CANARY_IDS[@]}"; do
  if jq -e --arg id "$id" --arg c "$CANARY" \
      'any(.results[]; (.path | startswith($c))
        and (.check_id == $id or (.check_id | endswith("." + $id))))' \
      "$OUT/semgrep.json" >/dev/null; then
    echo "ok       $id"
  else
    echo "MISSING  $id" >&2
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  echo "canary check failed: the scan did not fire as expected" >&2
  exit 1
fi

echo "== findings (canary excluded)"
jq -r --arg c "$CANARY" '.paths.scanned[] | select(startswith($c) | not)' \
  "$OUT/semgrep.json" > "$OUT/semgrep-scanned.txt"
jq -r --arg c "$CANARY" '
  [.results[] | select(.path | startswith($c) | not)] as $r
  | "findings: \($r | length), unique rules: \($r | map(.check_id) | unique | length), semgrep errors: \(.errors | length)",
    ($r | group_by(.check_id)[]
      | "\(length)  \(.[0].check_id)  \(map("\(.path):\(.start.line)") | join(" "))")
' "$OUT/semgrep.json"
echo "files scanned: $(wc -l < "$OUT/semgrep-scanned.txt") (list in $OUT/semgrep-scanned.txt)"

# set TRIVY_SKIP_DB_UPDATE=true / TRIVY_SKIP_JAVA_DB_UPDATE=true to freeze the
# DBs for a before/after comparison; docker passes them only when set
trivy() {
  docker run --rm ${docker_user[@]+"${docker_user[@]}"} \
    -e TRIVY_SKIP_DB_UPDATE -e TRIVY_SKIP_JAVA_DB_UPDATE \
    -v "$trivy_cache:/cache" -v "$SRC:/src:ro" -v "$SRC/$OUT:/out" \
    -v "$M2_MOUNT:$container_home/.m2:ro" -w /src \
    "$TRIVY_IMAGE" "$@"
}
trivy_flags=(--cache-dir /cache --disable-telemetry --quiet --list-all-pkgs --format json
  --ignorefile "/src/$IGNOREFILE" --show-suppressed)

echo "== trivy fs (pom.xml + secrets)"
rm -f "$OUT/trivy-fs.json" "$OUT/trivy-jar.json"
# --offline-scan: resolve the pom from ~/.m2 only, never maven central
trivy fs "${trivy_flags[@]}" --scanners vuln,secret --offline-scan \
  --skip-dirs target,scan-out,trivy-out,.git --output /out/trivy-fs.json .

echo "== trivy rootfs ($JAR)"
trivy rootfs "${trivy_flags[@]}" --scanners vuln --output /out/trivy-jar.json "/src/$JAR"

trivy version --cache-dir /cache --format json > "$OUT/trivy-version.json"
jq -r '"trivy \(.Version), vuln DB \(.VulnerabilityDB.UpdatedAt), java DB \(.JavaDB.UpdatedAt)"' \
  "$OUT/trivy-version.json"

echo "== trivy canary"
# trivy exits 0 on empty input; prove it actually resolved packages
trivy_failed=0
trivy_check() {
  if jq -e "$3" "$2" >/dev/null; then
    echo "ok       $1"
  else
    echo "FAILED   $1" >&2
    trivy_failed=1
  fi
}
trivy_check "pom.xml resolved, no empty versions" "$OUT/trivy-fs.json" \
  'any(.Results[]?; .Target == "pom.xml" and ((.Packages // []) | length > 0)
     and all(.Packages[]; (.Version // "") != ""))'
for pkg in org.springframework.boot:spring-boot org.apache.tomcat.embed:tomcat-embed-core; do
  trivy_check "$JAR contains $pkg" "$OUT/trivy-jar.json" \
    "any(.Results[]?.Packages[]?; .Name == \"$pkg\")"
done
if [ "$trivy_failed" -ne 0 ]; then
  echo "trivy canary failed: the scan did not see the dependencies" >&2
  exit 1
fi

echo "== secrets (rule and location only, never the match)"
jq -r '[.Results[]? | .Target as $t | .Secrets[]? | "\(.Severity)  \(.RuleID)  \($t):\(.StartLine)"]
  | "secrets: \(length)", .[]' "$OUT/trivy-fs.json"

echo "== repo (pom.xml) vs $JAR"
"$PY" scripts/trivy_report.py --diff --title "Repo (pom.xml + tests/requirements.txt) vs app.jar" --top 0 \
  "repo=$OUT/trivy-fs.json" "jar=$OUT/trivy-jar.json" > "$OUT/trivy-compare.md"
sed -n '/^## Repo/,/^## Trivy/p' "$OUT/trivy-compare.md" | sed '$d'
echo "full report: $OUT/trivy-compare.md"

if [ "${GATE:-1}" = 0 ]; then
  echo "== GATES OFF (GATE=0): findings above are reported only, nothing fails on them"
  exit 0
fi

# every gate reads json that is already written, so a red gate is never a
# network error; all gates run before the one exit at the end
echo "== gate: trivy (repo + $JAR)"
trivy_bad=$(jq -s '[.[] | .Results[]?.Vulnerabilities[]?
  | select(.Severity == "CRITICAL" or .Severity == "HIGH")] | length' \
  "$OUT/trivy-fs.json" "$OUT/trivy-jar.json")
jq -r -s '[.[] | .Results[]? | .Target as $t | .Vulnerabilities[]?
  | select(.Severity == "CRITICAL" or .Severity == "HIGH")
  | "\(.Severity)  \(.VulnerabilityID)  \(.PkgName) \(.InstalledVersion)  fixed: \(.FixedVersion // "none")  \($t)"]
  | unique | .[]' "$OUT/trivy-fs.json" "$OUT/trivy-jar.json"
echo "critical+high: $trivy_bad"
secrets_found=$(jq '[.Results[]?.Secrets[]?] | length' "$OUT/trivy-fs.json")
echo "secrets: $secrets_found"
jq -r -s --arg f "$IGNOREFILE" '[.[] | .Results[]?.ExperimentalModifiedFindings[]?
  | .Finding.VulnerabilityID // .Finding.RuleID] | unique
  | "suppressed by \($f): \(length)\(if length > 0 then " (" + join(" ") + ")" else "" end)"' \
  "$OUT/trivy-fs.json" "$OUT/trivy-jar.json"

echo "== gate: semgrep (ERROR findings new since the base commit)"
# semgrep --baseline-commit checks out the base, so it needs a writable repo:
# scan a throwaway clone and keep the real checkout read-only
head_sha=$(git rev-parse HEAD)
base=${GATE_BASE:-}
if [ -z "$base" ]; then
  if [ "${GITHUB_EVENT_NAME:-}" = pull_request ]; then
    # the pr checkout is a merge commit; its first parent is the base branch
    base=$(git rev-parse HEAD^1)
  else
    base=$(git merge-base HEAD origin/main) \
      || die "no base commit: set GATE_BASE or fetch origin/main"
  fi
fi
git cat-file -e "$base^{commit}" 2>/dev/null \
  || die "base commit $base not found (shallow checkout?)"
git merge-base --is-ancestor "$base" HEAD \
  || die "base commit $base is not an ancestor of HEAD"
semgrep_new=0
if [ "$(git rev-parse "$base")" = "$head_sha" ]; then
  echo "base = HEAD ($head_sha): no new commits to check"
else
  echo "base $base, head $head_sha (committed changes only)"
  tmp=$(mktemp -d)
  # native path for git, jq and docker (git bash: C:/..., linux: unchanged)
  work="$(cygpath -m "$tmp" 2>/dev/null || echo "$tmp")"
  clone="$work/repo"
  git clone -q --no-hardlinks --no-checkout . "$clone"
  git -C "$clone" -c advice.detachedHead=false checkout -q --detach "$head_sha"
  rm -f "$OUT/semgrep-gate.json"
  rc=0
  docker run --rm ${docker_user[@]+"${docker_user[@]}"} \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src \
    -v "$clone:/src" -v "$SRC/$OUT:/out" -w /src \
    "$SEMGREP_IMAGE" semgrep scan --metrics=off --quiet \
    --config p/java --config p/owasp-top-ten --config p/github-actions \
    --config "r/$REQUEST_MAPPING_RULE" --config .semgrep/rules/ \
    --severity ERROR --exclude .semgrep/canary --disable-nosem \
    --baseline-commit "$base" --json --output /out/semgrep-gate.json . || rc=$?
  if [ "$rc" -ne 0 ]; then
    if [ -s "$OUT/semgrep-gate.json" ]; then
      jq -r '.errors[]? | "  \(.type // "error"): \(.message // .)"' "$OUT/semgrep-gate.json" >&2
    fi
    die "semgrep gate scan failed (exit $rc)"
  fi
  # the gate scan has no canary of its own: every changed file that the full
  # scan covers must also be in the gate's scanned list
  git diff --name-only "$base" "$head_sha" > "$work/changed.txt"
  not_scanned=$(jq -rn --rawfile changed "$work/changed.txt" \
    --rawfile full "$OUT/semgrep-scanned.txt" --slurpfile gate "$OUT/semgrep-gate.json" '
    def lines: split("\n") | map(sub("\r$"; "")) | map(select(. != ""));
    ($full | lines) as $f | ($gate[0].paths.scanned // []) as $g
    | $changed | lines | .[]
    | select(. as $x | any($f[]; . == $x) and (any($g[]; . == $x) | not))')
  if [ -n "$not_scanned" ]; then
    echo "$not_scanned" >&2
    die "semgrep gate did not scan these changed files"
  fi
  semgrep_new=$(jq '.results | length' "$OUT/semgrep-gate.json")
  jq -r '.results[] | "\(.extra.severity)  \(.check_id)  \(.path):\(.start.line)"' \
    "$OUT/semgrep-gate.json"
fi
echo "new ERROR findings: $semgrep_new"

echo "== gate result"
failed=()
[ "$trivy_bad" -eq 0 ] || failed+=("trivy: $trivy_bad CRITICAL/HIGH finding(s) in the repo or $JAR")
[ "$secrets_found" -eq 0 ] || failed+=("trivy: $secrets_found secret(s) in the repo")
[ "$semgrep_new" -eq 0 ] || failed+=("semgrep: $semgrep_new new ERROR finding(s)")
if [ "${#failed[@]}" -gt 0 ]; then
  for f in "${failed[@]}"; do
    echo "FAILED   $f" >&2
    if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error title=Security gate::$f"; fi
  done
  gate_exit=1
  exit 10
fi
echo "all gates passed"

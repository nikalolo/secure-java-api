#!/usr/bin/env bash
# Code scan: Semgrep (registry packs + custom rules) and Trivy (pom.xml, app.jar,
# secrets) via Docker. Requires: docker, jq, python, ~/.m2 and a fresh
# target/app.jar (./mvnw -B -ntp package -DskipTests). Report-only: findings
# never fail the script, tool errors and a silent canary do.
set -euo pipefail

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
trivy_flags=(--cache-dir /cache --disable-telemetry --quiet --list-all-pkgs --format json)

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
"$PY" scripts/trivy_report.py --diff --title "Repo (pom.xml) vs app.jar" --top 0 \
  "repo=$OUT/trivy-fs.json" "jar=$OUT/trivy-jar.json" > "$OUT/trivy-compare.md"
sed -n '/^## Repo/,/^## Trivy/p' "$OUT/trivy-compare.md" | sed '$d'
echo "full report: $OUT/trivy-compare.md"

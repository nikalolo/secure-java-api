#!/usr/bin/env bash
# Code scan: Semgrep (registry packs + custom rules) via Docker.
# Requires: docker, jq. Report-only: findings never fail the script,
# tool errors and a silent canary do.
set -euo pipefail

cd "$(dirname "$0")/.."

# git bash rewrites /src-style args; docker desktop wants a D:/... mount path
export MSYS_NO_PATHCONV=1
SRC="$(pwd -W 2>/dev/null || pwd)"
OUT=scan-out
# digest-pinned: tags can be moved (aquasec/trivy, march 2026)
SEMGREP_IMAGE="semgrep/semgrep:1.184.0@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed"
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
mkdir -p "$OUT"

# on linux ci, run as the runner user so output files aren't root-owned
docker_user=()
if [ "$(uname -s)" = Linux ]; then
  docker_user=(--user "$(id -u):$(id -g)" -e HOME=/tmp -e XDG_CACHE_HOME=/tmp/.cache)
fi

semgrep() {
  docker run --rm ${docker_user[@]+"${docker_user[@]}"} -v "$SRC:/src" -w /src \
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
  --json --output "$OUT/semgrep.json" . || rc=$?
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

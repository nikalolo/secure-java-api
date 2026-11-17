#!/usr/bin/env bash
# Hardened image gate: CRITICAL findings that have a fix, minus dated entries
# in .trivyignore. Reads the trivy DBs already in the trivy-cache volume and
# never downloads them. usage: TRIVY_IMAGE=... scripts/image-gate.sh IMAGE SCAN_JSON
# SCAN_JSON is the earlier full scan of IMAGE (with --list-all-pkgs).
# Exit 10: the gate failed. Exit 1: a tool or setup error.
set -euo pipefail

# 10 is reserved for the gate result; any other failure leaves with 1
gate_exit=0
cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$gate_exit" -eq 0 ]; then exit 1; fi
}
trap cleanup EXIT

cd "$(dirname "$0")/.."
image=${1:?usage: image-gate.sh IMAGE SCAN_JSON}
json=${2:?usage: image-gate.sh IMAGE SCAN_JSON}
# no default here: the digest lives in the workflows and code-scan.sh
: "${TRIVY_IMAGE:?set TRIVY_IMAGE to the digest-pinned trivy image}"
IGNOREFILE=.trivyignore

command -v jq >/dev/null || { echo "jq not found on PATH" >&2; exit 1; }
[ -f "$IGNOREFILE" ] || { echo "$IGNOREFILE missing" >&2; exit 1; }
[ -f "$json" ] || { echo "$json missing" >&2; exit 1; }

# a zero only counts if the scan saw the app's own dependencies
if ! jq -e 'any(.Results[]?.Packages[]?; .Name == "org.apache.tomcat.embed:tomcat-embed-core")' \
    "$json" >/dev/null; then
  echo "canary failed: $json lists no tomcat-embed-core (scan without --list-all-pkgs, or the jar was not seen)" >&2
  exit 1
fi
echo "canary ok: tomcat-embed-core in $json"

# git bash would rewrite the container paths; docker desktop wants a C:\ path
ignore_mount="$(cygpath -w "$PWD/$IGNOREFILE" 2>/dev/null || echo "$PWD/$IGNOREFILE")"
rc=0
MSYS_NO_PATHCONV=1 docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$ignore_mount:/.trivyignore:ro" \
  -v trivy-cache:/root/.cache/trivy \
  "$TRIVY_IMAGE" image --skip-db-update --skip-java-db-update --disable-telemetry --quiet \
  --severity CRITICAL --ignore-unfixed --ignorefile /.trivyignore --exit-code 10 \
  "$image" || rc=$?

case "$rc" in
  0)
    echo "image gate passed: no fixable CRITICAL findings in $image"
    ;;
  10)
    msg="trivy: fixable CRITICAL finding(s) in $image (table above)"
    echo "FAILED   $msg" >&2
    if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error title=Security gate::$msg"; fi
    gate_exit=1
    exit 10
    ;;
  *)
    echo "trivy image gate scan failed (exit $rc)" >&2
    exit 1
    ;;
esac

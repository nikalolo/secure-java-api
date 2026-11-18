#!/usr/bin/env bash
# Workflow lint gate: actionlint (with its bundled shellcheck) and zizmor
# (regular persona) over .github/, both from digest-pinned containers with the
# repo mounted read-only. zizmor runs online when GH_TOKEN is set.
# Exit 10: a finding. Exit 1: a tool or setup error.
set -euo pipefail

# 10 is reserved for the gate result; any other failure leaves with 1
gate_exit=0
cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$gate_exit" -eq 0 ]; then exit 1; fi
}
trap cleanup EXIT

cd "$(dirname "$0")/.."
# not updated by dependabot (refs inside scripts); checked by hand
ACTIONLINT_IMAGE=rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
ZIZMOR_IMAGE=ghcr.io/zizmorcore/zizmor:1.32.0@sha256:3014cc8f68f663935f69b3c3e0e41f5ce102b268d97db13db0f62208747f860d
OUT=scan-out/lint

command -v jq >/dev/null || { echo "jq not found on PATH" >&2; exit 1; }
mkdir -p "$OUT"
# git bash would rewrite the container paths; docker desktop wants a C:\ path
src="$(pwd -W 2>/dev/null || pwd)"
findings=0

echo "== actionlint"
rc=0
MSYS_NO_PATHCONV=1 docker run --rm -v "$src:/repo:ro" -w /repo \
  "$ACTIONLINT_IMAGE" -color || rc=$?
case "$rc" in
  0) echo "actionlint: no problems" ;;
  # 1 = problems found; 2 = bad option, 3 = fatal
  1) echo "FAILED   actionlint reported problems (above)" >&2; findings=$((findings + 1)) ;;
  *) echo "actionlint failed (exit $rc)" >&2; exit 1 ;;
esac

echo "== zizmor"
token_env=()
if [ -n "${GH_TOKEN:-}" ]; then token_env=(-e GH_TOKEN); echo "mode: online"; else echo "mode: offline (GH_TOKEN not set)"; fi
# zizmor's own exit codes rise with severity (13 = medium) and would clash
# with our 10, so it reports with --no-exit-codes and jq does the counting
rc=0
MSYS_NO_PATHCONV=1 docker run --rm "${token_env[@]}" -v "$src:/repo:ro" -w /repo \
  "$ZIZMOR_IMAGE" --format json-v1 --no-exit-codes . \
  >"$OUT/zizmor.json" 2>"$OUT/zizmor.log" || rc=$?
if [ "$rc" -ne 0 ]; then
  cat "$OUT/zizmor.log" >&2
  echo "zizmor failed (exit $rc)" >&2
  exit 1
fi

# zizmor only warns on a file it cannot parse and audits the rest, so a zero
# only counts if every workflow plus dependabot.yml was audited
expected="$(find .github/workflows -maxdepth 1 \( -name '*.yml' -o -name '*.yaml' \) | wc -l)"
[ -f .github/dependabot.yml ] && expected=$((expected + 1))
audited="$(grep -c 'completed ' "$OUT/zizmor.log" || true)"
if [ "$audited" -ne "$expected" ]; then
  cat "$OUT/zizmor.log" >&2
  echo "zizmor audited $audited of $expected files" >&2
  exit 1
fi
echo "zizmor audited $audited/$expected files"

open="$(jq '[.[] | select(.ignored | not)] | length' "$OUT/zizmor.json")"
if [ "$open" -gt 0 ]; then
  jq -r '.[] | select(.ignored | not)
    | "  \(.ident)  \(.determinations.severity)  \(.locations[0].symbolic.key.Local.verbatim_path // "?")"' \
    "$OUT/zizmor.json"
  echo "FAILED   zizmor: $open finding(s)" >&2
  findings=$((findings + open))
else
  echo "zizmor: no findings"
fi

# context only: pedantic adds style findings that are not gated
echo "== zizmor pedantic (not gated)"
MSYS_NO_PATHCONV=1 docker run --rm "${token_env[@]}" -v "$src:/repo:ro" -w /repo \
  "$ZIZMOR_IMAGE" --persona pedantic --no-exit-codes --quiet . \
  | tee "$OUT/zizmor-pedantic.txt" | tail -n 1

if [ "$findings" -gt 0 ]; then
  msg="workflow lint: $findings problem(s), see the log above"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error title=Security gate::$msg"; fi
  gate_exit=1
  exit 10
fi
echo "workflow lint passed"

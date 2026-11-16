#!/usr/bin/env bash
# gitleaks scan of full git history, with a positive control first.
# usage: [LOG_OPTS=...] scripts/history-scan.sh [OUTDIR]
# LOG_OPTS defaults to "--all --reflog" (local); ci uses "--all".
# exit 10: the repo has a leak. exit 1: a tool or setup error.
set -euo pipefail

# 10 is reserved for a found leak; any other failure leaves with 1
gate_exit=0
ctl=""
cleanup() {
  local rc=$?
  if [ -n "$ctl" ]; then rm -rf "$ctl"; fi
  if [ "$rc" -ne 0 ] && [ "$gate_exit" -eq 0 ]; then exit 1; fi
}
trap cleanup EXIT

GITLEAKS_IMAGE="ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
repo=$(git rev-parse --show-toplevel)
# a shallow clone holds one commit, and the count check below would still pass
if [ "$(git -C "$repo" rev-parse --is-shallow-repository)" != false ]; then
  echo "$repo is a shallow clone; fetch the full history (fetch-depth: 0)" >&2
  exit 1
fi
out=${1:-$repo/scan-out/history}
mkdir -p "$out"
out=$(cd "$out" && pwd)  # docker needs an absolute path
# gitleaks splits log-opts on single spaces: no double or trailing spaces
LOG_OPTS=${LOG_OPTS:---all --reflog}
win() { cygpath -w "$1" 2>/dev/null || echo "$1"; }

# on linux ci, run as the runner user so the report isn't root-owned
docker_user=()
if [ "$(uname -s)" = Linux ]; then
  docker_user=(--user "$(id -u):$(id -g)" -e HOME=/tmp)
fi

# expected = commits with at least one added line in the log gitleaks reads;
# it scans added lines only, so empty and deletion-only commits don't count
expected_commits() {
  # shellcheck disable=SC2086  # LOG_OPTS is meant to split
  git -C "$1" log -p -U0 --full-history $LOG_OPTS --format='@@COMMIT %H' |
    awk '/^@@COMMIT /{c=$2; seen[c]=0; next}
         /^\+\+\+ /{next}
         /^\+/{if (c != "") seen[c]=1}
         END{n=0; for (k in seen) n+=seen[k]; print n}'
}

# scan REPO OUT: runs gitleaks, checks errors, commit count and redaction;
# sets $leaks
scan() {
  local r=$1 o=$2 expected scanned unredacted
  mkdir -p "$o"
  rm -f "$o/gitleaks.json"
  expected=$(expected_commits "$r")
  # git bash would rewrite /repo and /out; only docker gets this, git.exe needs the conversion
  MSYS_NO_PATHCONV=1 docker run --rm ${docker_user[@]+"${docker_user[@]}"} \
    -v "$(win "$r"):/repo:ro" -v "$(win "$o"):/out" \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/repo \
    "$GITLEAKS_IMAGE" git /repo --no-banner --no-color --redact --exit-code 0 \
    --log-opts="$LOG_OPTS" --report-format json --report-path /out/gitleaks.json \
    2> "$o/gitleaks.log"
  # gitleaks exits 0 even when git fails, so check its log ourselves
  if grep -E "(^| )ERR |fatal:" "$o/gitleaks.log" >&2; then
    echo "gitleaks/git reported an error" >&2
    exit 1
  fi
  scanned=$(sed -n 's/.* \([0-9][0-9]*\) commits scanned.*/\1/p' "$o/gitleaks.log" | tail -1)
  echo "commits scanned: ${scanned:-none} (expected $expected)"
  [ "${scanned:-x}" = "$expected" ] || { echo "commit count mismatch" >&2; exit 1; }
  leaks=$(jq 'length' "$o/gitleaks.json")
  unredacted=$(jq '[.[] | select(.Secret != "REDACTED" or .Match != "REDACTED")] | length' "$o/gitleaks.json")
  echo "leaks: $leaks, not redacted in report: $unredacted"
  [ "$unredacted" -eq 0 ] || { echo "report holds unredacted secrets" >&2; exit 1; }
  jq -r '.[] | "  \(.RuleID)  \(.File):\(.StartLine)  commit \(.Commit[0:7])"' "$o/gitleaks.json"
}

# positive control: fake key added then deleted, plus an empty commit.
# key is split so this file itself doesn't match the rule
echo "== positive control"
ctl=$(mktemp -d)
key="AK""IA""Q7XK2M4PZR5TB3WN"
g() { git -C "$ctl/repo" -c user.name=control -c user.email=control@example.invalid -c commit.gpgsign=false -c core.autocrlf=false "$@"; }
git init -q "$ctl/repo"
echo control > "$ctl/repo/README"; g add README; g commit -qm init
echo "aws_access_key_id = $key" > "$ctl/repo/config.ini"; g add config.ini; g commit -qm "add config"
g rm -q config.ini; g commit -qm "remove config"
g commit -q --allow-empty -m empty
scan "$ctl/repo" "$ctl/out"
[ "$leaks" -ge 1 ] || { echo "control: fake key not detected" >&2; exit 1; }
if grep -qF "$key" "$ctl/out/gitleaks.json" "$ctl/out/gitleaks.log"; then
  echo "control: key appears in report or log" >&2
  exit 1
fi
echo "control ok"

echo "== $repo"
scan "$repo" "$out"

if [ "$leaks" -gt 0 ]; then
  msg="gitleaks: $leaks leak(s) in the git history (report: $out/gitleaks.json, redacted)"
  echo "FAILED   $msg" >&2
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error title=Security gate::$msg"; fi
  gate_exit=1
  exit 10
fi
echo "no leaks"

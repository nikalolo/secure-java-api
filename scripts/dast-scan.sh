#!/usr/bin/env bash
# DAST gate: runs IMAGE and OWASP ZAP (passive rules, plan in .zap/plan.yaml)
# on an internal docker network with no egress, both containers locked down.
# usage: scripts/dast-scan.sh IMAGE   (build the image first)
# Exit 10: a finding (wrong status code or missing security header, or a ZAP
# alert Low or higher not covered by .zap/accepted-risks). Exit 1: a tool or
# setup error (app never healthy, zap failed, report or canary missing).
set -euo pipefail

# 10 is reserved for the gate result; any other failure leaves with 1.
# containers and the network are removed whatever happened.
gate_exit=0
net="" app="" zap=""
cleanup() {
  local rc=$?
  if [ -n "$zap" ]; then docker rm -f "$zap" >/dev/null 2>&1 || true; fi
  if [ -n "$app" ]; then docker rm -f "$app" >/dev/null 2>&1 || true; fi
  if [ -n "$net" ]; then docker network rm "$net" >/dev/null 2>&1 || true; fi
  if [ "$rc" -ne 0 ] && [ "$gate_exit" -eq 0 ]; then exit 1; fi
  exit "$rc"
}
trap cleanup EXIT
die() { echo "$*" >&2; exit 1; }

cd "$(dirname "$0")/.."
image=${1:?usage: dast-scan.sh IMAGE}
# not updated by dependabot (ref inside a script); checked by hand
ZAP_IMAGE=zaproxy/zap-bare:2.17.0@sha256:30b1344efc23bcb7568c56e61a12b907c6e8072b43a49f86318c3f9b9e56f2a2
PLAN=.zap/plan.yaml
ACCEPTED=.zap/accepted-risks
OUT=scan-out/dast
TARGET=http://app:8080
CSP="default-src 'none'; frame-ancestors 'none'"
# git bash would rewrite the container paths; this script runs no native git
export MSYS_NO_PATHCONV=1

command -v jq >/dev/null || die "jq not found on PATH"
[ -f "$PLAN" ] || die "$PLAN missing"
docker image inspect "$image" >/dev/null 2>&1 || die "image $image not found; build it first"
mkdir -p "$OUT"
rm -f "$OUT/dast.json" "$OUT/zap.log" "$OUT/summary.md"

# accepted risks: every entry needs a reason and a review date, so nothing is
# waived silently or forever
echo "== $ACCEPTED lint"
[ -f "$ACCEPTED" ] || die "$ACCEPTED missing (a file with only comments is fine)"
today=$(date -u +%F)
max_exp=$(date -u -d "+90 days" +%F)
entry_re='^([0-9]{1,6}) exp:([0-9]{4}-[0-9]{2}-[0-9]{2})$'
reason_re='^# reason: [^ ]'
declare -A accepted=() listed=()
prev="" n=0 lint_failed=0
while IFS= read -r line || [ -n "$line" ]; do
  n=$((n + 1))
  line=${line%$'\r'}
  case "$line" in "" | "#"*) prev=$line; continue ;; esac
  if [[ ! "$line" =~ $entry_re ]]; then
    echo "line $n: expected '<zap rule id> exp:YYYY-MM-DD', got: $line" >&2
    lint_failed=1
  else
    id=${BASH_REMATCH[1]} exp=${BASH_REMATCH[2]}
    # one entry per rule, so there is exactly one reason and one date to review
    if [ -n "${listed[$id]:-}" ]; then
      echo "line $n: rule $id is already listed on line ${listed[$id]}" >&2
      lint_failed=1
    fi
    listed[$id]=$n
    if ! date -u -d "$exp" +%F >/dev/null 2>&1; then
      echo "line $n: $exp is not a valid date" >&2
      lint_failed=1
    elif [[ "$exp" > "$max_exp" ]]; then
      echo "line $n: review date $exp is more than 90 days ahead (max $max_exp)" >&2
      lint_failed=1
    elif [[ ! "$exp" > "$today" ]]; then
      # not a lint error: the alert simply counts again
      echo "line $n: review date $exp for $id has passed; its alerts count again"
    else
      accepted[$id]=$exp
    fi
  fi
  if [[ ! "$prev" =~ $reason_re ]]; then
    echo "line $n: needs a '# reason: ...' line directly above" >&2
    lint_failed=1
  fi
  prev=$line
done < "$ACCEPTED"
[ "$lint_failed" -eq 0 ] || die "$ACCEPTED lint failed"
echo "active entries: ${#accepted[@]}"

# zap may only ever talk to the app under test: check every url before it runs
echo "== $PLAN target check"
mapfile -t urls < <(grep -oE '[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]"'"'"',}]+' "$PLAN" || true)
[ "${#urls[@]}" -gt 0 ] || die "no urls found in $PLAN"
bad=0
for u in "${urls[@]}"; do
  case "$u" in
    "$TARGET" | "$TARGET"/*) ;;
    *) echo "not the app under test: $u" >&2; bad=1 ;;
  esac
done
[ "$bad" -eq 0 ] || die "$PLAN points outside $TARGET"
grep -qF "$TARGET/health?password=zapcanary" "$PLAN" || die "$PLAN lost the canary request"
echo "urls: ${#urls[@]}, all on $TARGET"

# zap on linux runs as the runner user so it can write the runner-owned out dir
if [ "$(uname -s)" = Linux ]; then
  zap_uid=$(id -u) zap_gid=$(id -g)
  zap_user=(--user "$zap_uid:$zap_gid")
else
  zap_uid=1000 zap_gid=1000
  zap_user=()
fi
lockdown=(--read-only --cap-drop ALL --security-opt no-new-privileges:true)
# a throwaway container on the internal network, for curl
in_net() { docker run --rm --network "$net" "${lockdown[@]}" --entrypoint sh "$ZAP_IMAGE" -c "$1"; }

# refuse to scan unless the runtime is what we claim it is
assert_locked() { # $1 container
  local priv ro capdrop secopt user
  IFS='|' read -r priv ro capdrop secopt user < <(docker inspect "$1" --format \
    '{{.HostConfig.Privileged}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{.Config.User}}')
  echo "  $1: privileged=$priv read-only=$ro cap-drop=$capdrop security-opt=$secopt user=${user:-<image default>}"
  [ "$priv" = false ] || die "$1: runs privileged"
  [ "$ro" = true ] || die "$1: root filesystem is not read-only"
  [[ "$capdrop" == *'"ALL"'* ]] || die "$1: capabilities not dropped"
  [[ "$secopt" == *'no-new-privileges:true'* ]] || die "$1: no-new-privileges not set"
  [[ -n "$user" && ! "$user" =~ ^(0|root)(:|$) ]] || die "$1: runs as root"
}

echo "== start $image"
net=dast-net-$$ app=dast-app-$$ zap=dast-zap-$$
docker network create --internal "$net" >/dev/null
[ "$(docker network inspect "$net" --format '{{.Internal}}')" = true ] || die "$net is not internal"
docker run -d --name "$app" --network "$net" --network-alias app "${lockdown[@]}" \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m --memory 512m --pids-limit 200 "$image" >/dev/null
assert_locked "$app"
if ! in_net "i=0; while [ \$i -lt 60 ]; do curl -fs -m 2 -o /dev/null $TARGET/health && exit 0; i=\$((i + 1)); sleep 1; done; exit 1"; then
  echo "app did not answer GET /health within 60 s; last log lines:" >&2
  docker logs --tail 30 "$app" >&2 || true
  exit 1
fi
echo "app answers on $TARGET/health"

echo "== egress from $net (must fail)"
# shellcheck disable=SC2016 # $u and $rc expand inside the container
egress=$(in_net 'for u in https://github.com http://1.1.1.1; do rc=0; curl -s -m 5 -o /dev/null "$u" || rc=$?; echo "$u curl rc=$rc"; done')
while IFS= read -r l; do echo "  $l"; done <<< "$egress"
# only "no dns" (6) and "could not connect" (7) prove the block. not 28: with
# -m a timeout can also follow a connection that was made; 0, 35, 52 mean it got out
blocked=0
while read -r u _ rcfield; do
  case "${rcfield#rc=}" in
    6 | 7) blocked=$((blocked + 1)) ;;
    *) die "egress check: $u gave curl ${rcfield}, expected 6 or 7; the scan network is not isolated" ;;
  esac
done <<< "$egress"
[ "$blocked" -eq 2 ] || die "egress check: expected 2 blocked results, got $blocked"

# the script's own checks: status code and the security headers on every response
echo "== status and security headers"
checks=("GET /health 200" "POST /health 403" "GET /does-not-exist 403" "GET /error 403")
# "|", not tabs: read would merge the empty fields of missing headers.
# curl prints the -w line (code 000) even when the request fails.
fmt='%{http_code}|%header{x-content-type-options}|%header{x-frame-options}|%header{cache-control}|%header{content-security-policy}\n'
script=""
for c in "${checks[@]}"; do
  read -r m p _ <<< "$c"
  script+="curl -s -o /dev/null -m 5 -X $m -w '$fmt' $TARGET$p;"
done
mapfile -t rows < <(in_net "$script")
[ "${#rows[@]}" -eq "${#checks[@]}" ] || die "header check returned ${#rows[@]} rows, expected ${#checks[@]}"
matrix_fail=0
expect() { # $1 what, $2 got, $3 expected; uses $m $p, appends to ok
  if [ "$2" = "$3" ]; then ok+=(yes); return; fi
  ok+=(no)
  echo "FAILED   $m $p: $1 is '$2', expected '$3'" >&2
  matrix_fail=$((matrix_fail + 1))
}
{
  echo "### Status and security headers"
  echo
  echo "| Request | Status (expected) | nosniff | X-Frame-Options DENY | no-store | CSP |"
  echo "|---|---|---|---|---|---|"
} > "$OUT/summary.md"
for i in "${!checks[@]}"; do
  read -r m p want <<< "${checks[$i]}"
  IFS='|' read -r code xcto xfo cc csp <<< "${rows[$i]}"
  [ "$code" != 000 ] || die "$m $p: no answer from the app"
  ok=()
  expect "status" "$code" "$want"
  expect "X-Content-Type-Options" "$xcto" nosniff
  expect "X-Frame-Options" "$xfo" DENY
  # cache-control holds several directives; only no-store matters here
  if [[ "$cc" == *no-store* ]]; then expect "Cache-Control no-store" yes yes
  else expect "Cache-Control no-store" "$cc" "*no-store*"; fi
  expect "Content-Security-Policy" "$csp" "$CSP"
  printf '  %-24s %s (expected %s)  nosniff=%s xfo=%s no-store=%s csp=%s\n' \
    "$m $p" "$code" "$want" "${ok[1]}" "${ok[2]}" "${ok[3]}" "${ok[4]}"
  echo "| \`$m $p\` | $code ($want) | ${ok[1]} | ${ok[2]} | ${ok[3]} | ${ok[4]} |" >> "$OUT/summary.md"
done

echo "== zap"
plan_mount="$(cygpath -w "$PWD/.zap" 2>/dev/null || echo "$PWD/.zap")"
out_mount="$(cygpath -w "$PWD/$OUT" 2>/dev/null || echo "$PWD/$OUT")"
docker run -d --name "$zap" --network "$net" "${zap_user[@]}" "${lockdown[@]}" \
  --tmpfs "/home/zap:rw,uid=$zap_uid,gid=$zap_gid" --tmpfs "/tmp:rw,uid=$zap_uid,gid=$zap_gid" \
  --memory 2g --pids-limit 400 \
  -v "$plan_mount:/zap/plan:ro" -v "$out_mount:/zap/out:rw" \
  "$ZAP_IMAGE" zap.sh -cmd -silent -dir /home/zap/.ZAP -autorun /zap/plan/plan.yaml >/dev/null
assert_locked "$zap"
zap_rc=$(docker wait "$zap")
docker logs "$zap" > "$OUT/zap.log" 2>&1 || true
sed 's/^/  /' "$OUT/zap.log"
# automation framework: 0 ok, 1 plan error, 2 plan warnings; never alert-based
[ "$zap_rc" = 0 ] || die "zap exited $zap_rc (plan error or warning, log above)"

report="$OUT/dast.json"
[ -s "$report" ] || die "zap wrote no report ($report)"
jq -e --arg t "$TARGET" 'any(.site[]?; ."@name" == $t)' "$report" >/dev/null \
  || die "report has no results for $TARGET"
# a zero only counts if zap really looked: the canary must have fired
jq -e 'any(.site[].alerts[]?; .pluginid == "10024" and any(.instances[]?; .uri | contains("password=zapcanary")))' \
  "$report" >/dev/null || die "canary failed: no 10024 alert for the password=zapcanary request"
echo "canary ok: 10024 on the password=zapcanary request"

echo "== zap alerts"
{
  echo
  echo "### ZAP alerts"
  echo
  echo "| Rule | Risk | Name | URLs | Gate |"
  echo "|---|---|---|---|---|"
} >> "$OUT/summary.md"
gated=0
declare -A seen=()
while IFS=$'\t' read -r pid risk riskdesc name uris; do
  seen[$pid]=1
  if [ "$risk" -lt 1 ]; then
    verdict="info, not gated"
  elif [ -n "${accepted[$pid]:-}" ]; then
    verdict="accepted until ${accepted[$pid]}"
  else
    verdict="FAILED"
    gated=$((gated + 1))
  fi
  printf '  %-6s %-24s %s  %s  [%s]\n' "$pid" "$riskdesc" "$name" "$uris" "$verdict"
  echo "| $pid | $riskdesc | $name | $uris | $verdict |" >> "$OUT/summary.md"
done < <(jq -r --arg t "$TARGET" '.site[].alerts[]? | [.pluginid, .riskcode, .riskdesc, .name,
  ([.instances[]?.uri | sub("^" + $t; "")] | unique | join(" "))] | @tsv' "$report")
for id in "${!accepted[@]}"; do
  [ -n "${seen[$id]:-}" ] || echo "note: accepted rule $id did not fire; remove it from $ACCEPTED"
done

echo "== gate result"
echo "behaviour checks failed: $matrix_fail, zap alerts Low or higher not accepted: $gated"
if [ $((matrix_fail + gated)) -gt 0 ]; then
  msg="dast: $matrix_fail status/header check(s) failed, $gated zap alert(s) Low or higher not accepted (details above)"
  echo "FAILED   $msg" >&2
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error title=Security gate::$msg"; fi
  gate_exit=1
  exit 10
fi
echo "dast gate passed"

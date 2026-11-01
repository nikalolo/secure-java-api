#!/usr/bin/env bash
# Offline config scan: Checkov (Dockerfiles, GitHub Actions) + actionlint.
# Requires: checkov, actionlint and shellcheck on PATH
#   pip install checkov actionlint-py   # shellcheck: apt install shellcheck
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== actionlint"
actionlint -shellcheck="$(command -v shellcheck)"
echo "actionlint: no issues"

echo "== checkov"
# --skip-download: don't contact the vendor API; use bundled checks only.
checkov -d . --framework dockerfile github_actions --skip-download --compact --quiet

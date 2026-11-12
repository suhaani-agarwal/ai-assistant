#!/usr/bin/env bash
# Offline check of the pin pattern in adopt-ci.sh: --update-pin finds pinned references by this one regex, so a
# mistake in it makes the command skip every repository without an error.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pin_re=$(sed -n "s/^pin_re='\(.*\)'\$/\1/p" "$here/adopt-ci.sh")
[[ -n "$pin_re" ]] || { echo "FAIL: pin_re not found in adopt-ci.sh"; exit 1; }
sha=$(printf 'a%.0s' {1..40})
fail=0
expect() { # match|nomatch, line
  if grep -qE "uses:[[:space:]]*${pin_re}" <<< "$2"; then got=match; else got=nomatch; fi
  [[ "$got" == "$1" ]] || { echo "FAIL: expected $1: $2"; fail=1; }
}
expect match "    uses: kyverno/assistant/.github/workflows/pr-management.yml@${sha}"
expect match "    uses: kyverno/assistant/.github/workflows/issue-management.yml@${sha}"
expect match "        uses: kyverno/assistant/.github/actions/pr-management@${sha}"
expect match "        uses: other/fork/.github/actions/issue-management@${sha}"
expect match "    uses: kyverno/assistant/.github/workflows/issue-management-validate.yml@${sha}"
expect nomatch "    uses: kyverno/assistant/.github/workflows/pr-management.yml@main"
expect nomatch "    uses: actions/checkout@${sha}"
[[ "$fail" == "0" ]] && echo "ok"
exit "$fail"

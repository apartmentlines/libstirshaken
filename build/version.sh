#!/usr/bin/env bash
set -euo pipefail

readonly SEMVER_PATTERN='^[vV]?[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?$'

latest_semver_tag() {
  { git tag --list 2>/dev/null || true; } | awk -v pattern="${SEMVER_PATTERN}" '$0 ~ pattern { sub(/^[vV]/, "", $0); print }' | sort -V | tail -n 1
}

current_revision() {
  git rev-parse HEAD
}

main() {
  local version
  version="$(latest_semver_tag)"
  if [ -n "${version}" ]; then
    printf '%s\n' "${version}"
    return 0
  fi
  current_revision
}

main "$@"

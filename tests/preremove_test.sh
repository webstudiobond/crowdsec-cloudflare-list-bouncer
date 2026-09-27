#!/usr/bin/env bash
set -euo pipefail

test_preremove_help_short() {
  local output
  output="$(./scripts/preremove.sh -h)"
  assert_contains "Usage:" "${output}"
}

test_preremove_help_long() {
  local output
  output="$(./scripts/preremove.sh --help)"
  assert_contains "Usage:" "${output}"
}

test_preremove_invalid_argument() {
  local exit_code=0
  ./scripts/preremove.sh --unsupported-arg >/dev/null 2>&1 || exit_code=$?
  assert_equals "1" "${exit_code}"
}

test_preremove_default_execution() {
  assert_successful_code ./scripts/preremove.sh
}

test_preremove_remove_argument() {
  assert_successful_code ./scripts/preremove.sh remove
}

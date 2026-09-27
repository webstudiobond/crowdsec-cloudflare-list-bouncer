#!/usr/bin/env bash
set -euo pipefail

test_postinstall_help_short() {
  local output
  output="$(./scripts/postinstall.sh -h)"
  assert_contains "Usage:" "${output}"
}

test_postinstall_help_long() {
  local output
  output="$(./scripts/postinstall.sh --help)"
  assert_contains "Usage:" "${output}"
}

test_postinstall_invalid_argument() {
  local exit_code=0
  ./scripts/postinstall.sh --unsupported-arg >/dev/null 2>&1 || exit_code=$?
  assert_equals "1" "${exit_code}"
}

test_postinstall_default_execution() {
  assert_successful_code ./scripts/postinstall.sh
}

test_postinstall_configure_argument() {
  assert_successful_code ./scripts/postinstall.sh configure
}

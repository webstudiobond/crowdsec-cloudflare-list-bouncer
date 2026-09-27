#!/usr/bin/env bash
set -euo pipefail

set_up() {
  source ./scripts/postremove.sh
}

test_postremove_check_systemd_active() {
  local result
  result="$(check_systemd_active)"
  assert_not_empty "${result}"
}

test_postremove_help_short() {
  local output
  output="$(main -h)"
  assert_contains "Usage:" "${output}"
}

test_postremove_help_long() {
  local output
  output="$(main --help)"
  assert_contains "Usage:" "${output}"
}

test_postremove_invalid_argument() {
  local exit_code
  set +e
  (main --unsupported-arg) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_postremove_default_execution() {
  (main)
  assert_successful_code
}

test_postremove_remove_argument() {
  (main remove)
  assert_successful_code
}

test_postremove_purge_argument() {
  (main purge)
  assert_successful_code
}

test_postremove_trace_enabled() {
  local TRACE=1
  (main)
  assert_successful_code
}

test_postremove_reload_systemd_active() {
  (
    check_systemd_active() {
      printf "yes"
    }
    systemctl() {
      return 0
    }
    reload_systemd
    check_systemd_active >/dev/null
    systemctl >/dev/null 2>&1
  )
  assert_successful_code
}

test_postremove_direct_invocation_block() {
  local output
  output="$(
    export BASH_SOURCE_OVERRIDE="./scripts/postremove.sh"
    source ./scripts/postremove.sh -h
  )"
  assert_contains "Usage:" "${output}"
}

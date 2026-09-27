#!/usr/bin/env bash
set -euo pipefail

set_up() {
  source ./scripts/postinstall.sh
}

test_postinstall_check_systemd_active() {
  local result
  result="$(check_systemd_active)"
  assert_not_empty "${result}"
}

test_postinstall_help_short() {
  local output
  output="$(main -h)"
  assert_contains "Usage:" "${output}"
}

test_postinstall_help_long() {
  local output
  output="$(main --help)"
  assert_contains "Usage:" "${output}"
}

test_postinstall_invalid_argument() {
  local exit_code
  set +e
  (main --unsupported-arg) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_postinstall_default_execution() {
  (main)
  assert_successful_code
}

test_postinstall_configure_argument() {
  (main configure)
  assert_successful_code
}

test_postinstall_number_argument() {
  (main 1)
  assert_successful_code
}

test_postinstall_trace_enabled() {
  local TRACE=1
  (main)
  assert_successful_code
}

test_postinstall_configure_service_active_enabled() {
  (
    check_systemd_active() {
      printf "yes"
    }
    systemctl() {
      case "$1" in
      is-enabled)
        printf "enabled"
        ;;
      *)
        return 0
        ;;
      esac
    }
    configure_service
    check_systemd_active >/dev/null
    systemctl is-enabled >/dev/null 2>&1
  )
  assert_successful_code
}

test_postinstall_configure_service_active_disabled() {
  (
    check_systemd_active() {
      printf "yes"
    }
    systemctl() {
      case "$1" in
      is-enabled)
        return 1
        ;;
      *)
        return 0
        ;;
      esac
    }
    configure_service
    check_systemd_active >/dev/null
    systemctl daemon-reload >/dev/null 2>&1
  )
  assert_successful_code
}

test_postinstall_direct_invocation_block() {
  local output
  output="$(
    export BASH_SOURCE_OVERRIDE="./scripts/postinstall.sh"
    source ./scripts/postinstall.sh -h
  )"
  assert_contains "Usage:" "${output}"
}

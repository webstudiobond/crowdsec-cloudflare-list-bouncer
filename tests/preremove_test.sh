#!/usr/bin/env bash
set -euo pipefail

set_up() {
  source ./scripts/preremove.sh
}

test_preremove_check_systemd_active() {
  local result
  result="$(check_systemd_active)"
  assert_not_empty "${result}"
}

test_preremove_help_short() {
  local output
  output="$(main -h)"
  assert_contains "Usage:" "${output}"
}

test_preremove_help_long() {
  local output
  output="$(main --help)"
  assert_contains "Usage:" "${output}"
}

test_preremove_invalid_argument() {
  local exit_code
  set +e
  (main --unsupported-arg) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_preremove_default_execution() {
  (main)
  assert_successful_code
}

test_preremove_remove_argument() {
  (main remove)
  assert_successful_code
}

test_preremove_upgrade_argument() {
  (main upgrade)
  assert_successful_code
}

test_preremove_deconfigure_argument() {
  (main deconfigure)
  assert_successful_code
}

test_preremove_failed_upgrade_argument() {
  (main failed-upgrade)
  assert_successful_code
}

test_preremove_rpm_removal() {
  (main 0)
  assert_successful_code
}

test_preremove_rpm_upgrade() {
  (main 1)
  assert_successful_code
}

test_preremove_trace_enabled() {
  local TRACE=1
  (main)
  assert_successful_code
}

test_preremove_stop_and_disable_on_remove() {
  (
    check_systemd_active() {
      printf "yes"
    }
    systemctl() {
      return 0
    }
    stop_and_disable_service
    check_systemd_active >/dev/null
    systemctl >/dev/null 2>&1
  )
  assert_successful_code
}

test_preremove_stop_only_on_upgrade() {
  (
    check_systemd_active() {
      printf "yes"
    }
    systemctl() {
      return 0
    }
    stop_service
    check_systemd_active >/dev/null
    systemctl >/dev/null 2>&1
  )
  assert_successful_code
}

test_preremove_stop_service_systemd_inactive() {
  (
    check_systemd_active() {
      printf "no"
    }
    stop_service
    check_systemd_active >/dev/null
  )
  assert_successful_code
}

test_preremove_stop_and_disable_systemd_inactive() {
  (
    check_systemd_active() {
      printf "no"
    }
    stop_and_disable_service
    check_systemd_active >/dev/null
  )
  assert_successful_code
}

test_preremove_direct_invocation_block() {
  local output
  output="$(
    export BASH_SOURCE_OVERRIDE="./scripts/preremove.sh"
    source ./scripts/preremove.sh -h
  )"
  assert_contains "Usage:" "${output}"
}

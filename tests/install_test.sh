#!/usr/bin/env bash
set -euo pipefail

set_up() {
  source ./scripts/install.sh
}

test_install_help_short() {
  local output
  output="$(main -h)"
  assert_contains "Usage:" "${output}"
}

test_install_help_long() {
  local output
  output="$(main --help)"
  assert_contains "Usage:" "${output}"
}

test_install_invalid_argument() {
  local exit_code
  set +e
  (main --unsupported-option) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_has_command_true() {
  local result
  result="$(has_command bash)"
  assert_equals "yes" "${result}"
}

test_install_has_command_false() {
  local result
  result="$(has_command non_existent_binary_xyz)"
  assert_equals "no" "${result}"
}

test_install_check_dependencies_success() {
  check_dependencies
  assert_successful_code
}

test_install_check_dependencies_with_shasum_only() {
  (
    has_command() {
      case "$1" in
      sha256sum)
        printf "no"
        ;;
      *)
        printf "yes"
        ;;
      esac
    }
    check_dependencies
    has_command sha256sum >/dev/null
  )
  assert_successful_code
}

test_install_check_dependencies_missing_tool() {
  local exit_code
  set +e
  (
    has_command() {
      case "$1" in
      jq)
        printf "no"
        ;;
      *)
        printf "yes"
        ;;
      esac
    }
    check_dependencies
    has_command jq >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_check_dependencies_missing_hasher() {
  local exit_code
  set +e
  (
    has_command() {
      case "$1" in
      sha256sum | shasum)
        printf "no"
        ;;
      *)
        printf "yes"
        ;;
      esac
    }
    check_dependencies
    has_command sha256sum >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_detect_arch_amd64() {
  local result
  result="$(
    uname() {
      printf "x86_64\n"
    }
    detect_arch
    uname >/dev/null
  )"
  assert_equals "amd64" "${result}"
}

test_install_detect_arch_arm64() {
  local result
  result="$(
    uname() {
      printf "aarch64\n"
    }
    detect_arch
    uname >/dev/null
  )"
  assert_equals "arm64" "${result}"
}

test_install_detect_arch_unsupported() {
  local exit_code
  set +e
  (
    uname() {
      printf "mips\n"
    }
    detect_arch
    uname >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_detect_package_format_deb() {
  local result
  result="$(
    has_command() {
      case "$1" in
      dpkg)
        printf "yes"
        ;;
      *)
        printf "no"
        ;;
      esac
    }
    detect_package_format
    has_command dpkg >/dev/null
  )"
  assert_equals "deb" "${result}"
}

test_install_detect_package_format_rpm() {
  local result
  result="$(
    has_command() {
      case "$1" in
      rpm)
        printf "yes"
        ;;
      *)
        printf "no"
        ;;
      esac
    }
    detect_package_format
    has_command rpm >/dev/null
  )"
  assert_equals "rpm" "${result}"
}

test_install_detect_package_format_unknown() {
  local exit_code
  set +e
  (
    has_command() {
      printf "no"
    }
    detect_package_format
    has_command unknown >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_get_current_version_installed() {
  local result
  result="$(
    has_command() {
      case "$1" in
      "${BIN_NAME}")
        printf "yes"
        ;;
      *)
        printf "no"
        ;;
      esac
    }
    crowdsec-cloudflare-list-bouncer() {
      printf "version 1.2.3\n"
    }
    get_current_version
    has_command "${BIN_NAME}" >/dev/null
    crowdsec-cloudflare-list-bouncer >/dev/null
  )"
  assert_equals "1.2.3" "${result}"
}

test_install_get_current_version_none() {
  local result
  result="$(
    has_command() {
      printf "no"
    }
    get_current_version
    has_command none >/dev/null
  )"
  assert_equals "none" "${result}"
}

test_install_verify_checksum_empty() {
  local exit_code
  set +e
  (verify_checksum "/dev/null" "") >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_verify_checksum_null() {
  local exit_code
  set +e
  (verify_checksum "/dev/null" "null") >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_verify_checksum_sha256sum() {
  local temp_file
  temp_file="$(mktemp)"
  printf "test" >"${temp_file}"

  (
    has_command() {
      case "$1" in
      sha256sum)
        printf "yes"
        ;;
      *)
        printf "no"
        ;;
      esac
    }
    sha256sum() {
      return 0
    }
    verify_checksum "${temp_file}" "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    has_command sha256sum >/dev/null
    sha256sum >/dev/null
  )
  assert_successful_code
  rm -f "${temp_file}"
}

test_install_verify_checksum_shasum() {
  local temp_file
  temp_file="$(mktemp)"
  printf "test" >"${temp_file}"

  (
    has_command() {
      case "$1" in
      sha256sum)
        printf "no"
        ;;
      shasum)
        printf "yes"
        ;;
      *)
        printf "no"
        ;;
      esac
    }
    shasum() {
      return 0
    }
    verify_checksum "${temp_file}" "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    has_command shasum >/dev/null
    shasum >/dev/null
  )
  assert_successful_code
  rm -f "${temp_file}"
}

test_install_verify_checksum_failure() {
  local temp_file
  temp_file="$(mktemp)"
  printf "test" >"${temp_file}"

  local exit_code
  set +e
  (
    has_command() {
      case "$1" in
      sha256sum)
        printf "yes"
        ;;
      *)
        printf "no"
        ;;
      esac
    }
    sha256sum() {
      return 1
    }
    verify_checksum "${temp_file}" "invalidhash"
    has_command sha256sum >/dev/null
    sha256sum >/dev/null 2>&1
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
  rm -f "${temp_file}"
}

test_install_verify_checksum_no_hasher() {
  local exit_code
  set +e
  (
    has_command() {
      printf "no"
    }
    verify_checksum "/dev/null" "abc"
    has_command hasher >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_check_privileges_root() {
  (
    id() {
      printf "0\n"
    }
    check_privileges
    id >/dev/null
  )
  assert_successful_code
}

test_install_check_privileges_sudo() {
  (
    id() {
      printf "1000\n"
    }
    has_command() {
      case "$1" in
      sudo)
        printf "yes"
        ;;
      *)
        printf "no"
        ;;
      esac
    }
    check_privileges
    id >/dev/null
    has_command sudo >/dev/null
  )
  assert_successful_code
}

test_install_check_privileges_no_sudo() {
  local exit_code
  set +e
  (
    id() {
      printf "1000\n"
    }
    has_command() {
      printf "no"
    }
    check_privileges
    id >/dev/null
    has_command sudo >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_run_privileged_root() {
  (
    id() {
      printf "0\n"
    }
    run_privileged printf "ok"
    id >/dev/null
  )
  assert_successful_code
}

test_install_run_privileged_sudo() {
  (
    id() {
      printf "1000\n"
    }
    sudo() {
      "$@"
    }
    run_privileged printf "ok"
    id >/dev/null
    sudo true
  )
  assert_successful_code
}

test_install_main_missing_privileges() {
  local exit_code
  set +e
  (
    id() {
      printf "1000\n"
    }
    has_command() {
      printf "no"
    }
    main
    id >/dev/null
    has_command sudo >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_main_already_latest() {
  (
    check_dependencies() {
      return 0
    }
    detect_arch() {
      printf "amd64"
    }
    detect_package_format() {
      printf "deb"
    }
    curl() {
      printf '{"tag_name":"v1.0.0"}'
    }
    get_current_version() {
      printf "1.0.0"
    }
    main
    check_dependencies >/dev/null
    detect_arch >/dev/null
    detect_package_format >/dev/null
    curl "" >/dev/null
    get_current_version >/dev/null
  )
  assert_successful_code
}

test_install_main_trace_enabled() {
  local TRACE=1
  (
    check_dependencies() {
      return 0
    }
    detect_arch() {
      printf "amd64"
    }
    detect_package_format() {
      printf "deb"
    }
    curl() {
      printf '{"tag_name":"v1.0.0"}'
    }
    get_current_version() {
      printf "1.0.0"
    }
    main
    check_dependencies >/dev/null
    detect_arch >/dev/null
    detect_package_format >/dev/null
    curl "" >/dev/null
    get_current_version >/dev/null
  )
  assert_successful_code
}

test_install_main_api_query_failure() {
  local exit_code
  set +e
  (
    check_dependencies() {
      return 0
    }
    detect_arch() {
      printf "amd64"
    }
    detect_package_format() {
      printf "deb"
    }
    curl() {
      return 1
    }
    main
    check_dependencies >/dev/null
    detect_arch >/dev/null
    detect_package_format >/dev/null
    curl "" >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_main_missing_tag() {
  local exit_code
  set +e
  (
    check_dependencies() {
      return 0
    }
    detect_arch() {
      printf "amd64"
    }
    detect_package_format() {
      printf "deb"
    }
    curl() {
      printf '{}'
    }
    main
    check_dependencies >/dev/null
    detect_arch >/dev/null
    detect_package_format >/dev/null
    curl "" >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_main_missing_asset() {
  local exit_code
  set +e
  (
    check_dependencies() {
      return 0
    }
    detect_arch() {
      printf "amd64"
    }
    detect_package_format() {
      printf "deb"
    }
    curl() {
      printf '{"tag_name":"v1.0.0","assets":[]}'
    }
    get_current_version() {
      printf "none"
    }
    main
    check_dependencies >/dev/null
    detect_arch >/dev/null
    detect_package_format >/dev/null
    curl "" >/dev/null
    get_current_version >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_main_missing_download_url() {
  local exit_code
  set +e
  (
    check_dependencies() {
      return 0
    }
    detect_arch() {
      printf "amd64"
    }
    detect_package_format() {
      printf "deb"
    }
    curl() {
      printf '{"tag_name":"v1.0.0","assets":[{"name":"bouncer_amd64.deb"}]}'
    }
    get_current_version() {
      printf "none"
    }
    main
    check_dependencies >/dev/null
    detect_arch >/dev/null
    detect_package_format >/dev/null
    curl "" >/dev/null
    get_current_version >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_main_missing_checksum() {
  local exit_code
  set +e
  (
    check_dependencies() {
      return 0
    }
    detect_arch() {
      printf "amd64"
    }
    detect_package_format() {
      printf "deb"
    }
    curl() {
      printf '{"tag_name":"v1.0.0","assets":[{"name":"bouncer_amd64.deb","browser_download_url":"https://example.com/test.deb"}]}'
    }
    get_current_version() {
      printf "none"
    }
    main
    check_dependencies >/dev/null
    detect_arch >/dev/null
    detect_package_format >/dev/null
    curl "" >/dev/null
    get_current_version >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_main_download_failure() {
  local exit_code
  set +e
  (
    check_dependencies() {
      return 0
    }
    detect_arch() {
      printf "amd64"
    }
    detect_package_format() {
      printf "deb"
    }
    get_current_version() {
      printf "none"
    }
    curl() {
      case "$1" in
      -fSs)
        printf '{"tag_name":"v1.0.0","assets":[{"name":"bouncer_amd64.deb","browser_download_url":"https://example.com/test.deb","digest":"sha256:abc"}]}'
        ;;
      -fSsL)
        return 1
        ;;
      *)
        return 0
        ;;
      esac
    }
    verify_checksum() {
      return 0
    }
    run_privileged() {
      return 0
    }
    main
    check_dependencies >/dev/null
    detect_arch >/dev/null
    detect_package_format >/dev/null
    get_current_version >/dev/null
    curl "" >/dev/null
    verify_checksum "" "" >/dev/null
    run_privileged true >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_main_deb_success() {
  (
    check_dependencies() {
      return 0
    }
    detect_arch() {
      printf "amd64"
    }
    detect_package_format() {
      printf "deb"
    }
    get_current_version() {
      printf "none"
    }
    curl() {
      case "$1" in
      -fSs)
        printf '{"tag_name":"v1.0.0","assets":[{"name":"bouncer_amd64.deb","browser_download_url":"https://example.com/test.deb","digest":"sha256:abc"}]}'
        ;;
      -fSsL)
        touch "$4"
        ;;
      *)
        return 0
        ;;
      esac
    }
    verify_checksum() {
      return 0
    }
    run_privileged() {
      return 0
    }
    main
    check_dependencies >/dev/null
    detect_arch >/dev/null
    detect_package_format >/dev/null
    get_current_version >/dev/null
    curl "" >/dev/null
    verify_checksum "" "" >/dev/null
    run_privileged true >/dev/null
  )
  assert_successful_code
}

test_install_main_rpm_success() {
  (
    check_dependencies() {
      return 0
    }
    detect_arch() {
      printf "arm64"
    }
    detect_package_format() {
      printf "rpm"
    }
    get_current_version() {
      printf "none"
    }
    curl() {
      case "$1" in
      -fSs)
        printf '{"tag_name":"v1.0.0","assets":[{"name":"bouncer_arm64.rpm","browser_download_url":"https://example.com/test.rpm","digest":"sha256:abc"}]}'
        ;;
      -fSsL)
        touch "$4"
        ;;
      *)
        return 0
        ;;
      esac
    }
    verify_checksum() {
      return 0
    }
    run_privileged() {
      return 0
    }
    main
    check_dependencies >/dev/null
    detect_arch >/dev/null
    detect_package_format >/dev/null
    get_current_version >/dev/null
    curl "" >/dev/null
    verify_checksum "" "" >/dev/null
    run_privileged true >/dev/null
  )
  assert_successful_code
}

test_install_main_unsupported_package_format() {
  local exit_code
  set +e
  (
    check_dependencies() {
      return 0
    }
    detect_arch() {
      printf "amd64"
    }
    detect_package_format() {
      printf "apk"
    }
    get_current_version() {
      printf "none"
    }
    curl() {
      case "$1" in
      -fSs)
        printf '{"tag_name":"v1.0.0","assets":[{"name":"bouncer_amd64.apk","browser_download_url":"https://example.com/test.apk","digest":"sha256:abc"}]}'
        ;;
      -fSsL)
        touch "$4"
        ;;
      *)
        return 0
        ;;
      esac
    }
    verify_checksum() {
      return 0
    }
    run_privileged() {
      return 0
    }
    main
    check_dependencies >/dev/null
    detect_arch >/dev/null
    detect_package_format >/dev/null
    get_current_version >/dev/null
    curl "" >/dev/null
    verify_checksum "" "" >/dev/null
    run_privileged true >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_install_direct_invocation_block() {
  local output
  output="$(
    export BASH_SOURCE_OVERRIDE="./scripts/install.sh"
    source ./scripts/install.sh -h
  )"
  assert_contains "Usage:" "${output}"
}

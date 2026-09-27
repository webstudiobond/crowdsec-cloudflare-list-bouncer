#!/usr/bin/env bash
set -euo pipefail

set_up() {
  source ./scripts/generate-repo.sh
}

test_generate_repo_help_short() {
  local output
  output="$(main -h)"
  assert_contains "Usage:" "${output}"
}

test_generate_repo_help_long() {
  local output
  output="$(main --help)"
  assert_contains "Usage:" "${output}"
}

test_generate_repo_missing_all_args() {
  local exit_code
  set +e
  (main) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_generate_repo_missing_output_dir() {
  local exit_code
  set +e
  (main "/dev/null") >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_generate_repo_nonexistent_new_packages_dir() {
  local exit_code
  set +e
  (main "/nonexistent/path/xyz" "/tmp/output") >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_generate_repo_has_command_true() {
  local result
  result="$(has_command bash)"
  assert_equals "yes" "${result}"
}

test_generate_repo_has_command_false() {
  local result
  result="$(has_command nonexistent_binary_xyz)"
  assert_equals "no" "${result}"
}

test_generate_repo_check_dependencies_success() {
  (
    has_command() {
      printf "yes"
    }
    check_dependencies
    has_command "" >/dev/null
  )
  assert_successful_code
}

test_generate_repo_check_dependencies_missing() {
  local exit_code
  set +e
  (
    has_command() {
      case "$1" in
      createrepo_c)
        printf "no"
        ;;
      *)
        printf "yes"
        ;;
      esac
    }
    check_dependencies
    has_command createrepo_c >/dev/null
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_generate_repo_import_key_missing_env() {
  local exit_code
  set +e
  (
    unset GPG_PRIVATE_KEY
    import_gpg_key
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_generate_repo_import_key_no_passphrase_success() {
  local GPG_PRIVATE_KEY="mock_key"
  (
    unset GPG_PASSPHRASE
    gpg() {
      return 0
    }
    import_gpg_key
    gpg >/dev/null
  )
  assert_successful_code
}

test_generate_repo_import_key_no_passphrase_failure() {
  local GPG_PRIVATE_KEY="mock_key"
  local exit_code
  set +e
  (
    unset GPG_PASSPHRASE
    gpg() {
      return 1
    }
    import_gpg_key
    gpg >/dev/null 2>&1
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_generate_repo_import_key_with_passphrase_success() {
  local GPG_PRIVATE_KEY="mock_key"
  local GPG_PASSPHRASE="secret"
  (
    gpg() {
      return 0
    }
    import_gpg_key
    gpg >/dev/null
  )
  assert_successful_code
}

test_generate_repo_sign_detached_no_passphrase_success() {
  (
    unset GPG_PASSPHRASE
    gpg() {
      return 0
    }
    sign_detached "/dev/null" "/dev/null"
    gpg >/dev/null
  )
  assert_successful_code
}

test_generate_repo_sign_detached_no_passphrase_failure() {
  local exit_code
  set +e
  (
    unset GPG_PASSPHRASE
    gpg() {
      return 1
    }
    sign_detached "/dev/null" "/dev/null"
    gpg >/dev/null 2>&1
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_generate_repo_sign_detached_with_passphrase_success() {
  local GPG_PASSPHRASE="secret"
  (
    gpg() {
      return 0
    }
    sign_detached "/dev/null" "/dev/null"
    gpg >/dev/null
  )
  assert_successful_code
}

test_generate_repo_sign_detached_with_passphrase_failure() {
  local GPG_PASSPHRASE="secret"
  local exit_code
  set +e
  (
    gpg() {
      return 1
    }
    sign_detached "/dev/null" "/dev/null"
    gpg >/dev/null 2>&1
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_generate_repo_sign_clearsign_no_passphrase_success() {
  (
    unset GPG_PASSPHRASE
    gpg() {
      return 0
    }
    sign_clearsign "/dev/null" "/dev/null"
    gpg >/dev/null
  )
  assert_successful_code
}

test_generate_repo_sign_clearsign_no_passphrase_failure() {
  local exit_code
  set +e
  (
    unset GPG_PASSPHRASE
    gpg() {
      return 1
    }
    sign_clearsign "/dev/null" "/dev/null"
    gpg >/dev/null 2>&1
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_generate_repo_sign_clearsign_with_passphrase_success() {
  local GPG_PASSPHRASE="secret"
  (
    gpg() {
      return 0
    }
    sign_clearsign "/dev/null" "/dev/null"
    gpg >/dev/null
  )
  assert_successful_code
}

test_generate_repo_sign_clearsign_with_passphrase_failure() {
  local GPG_PASSPHRASE="secret"
  local exit_code
  set +e
  (
    gpg() {
      return 1
    }
    sign_clearsign "/dev/null" "/dev/null"
    gpg >/dev/null 2>&1
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
}

test_generate_repo_rotate_packages_under_limit() {
  local test_dir
  test_dir="$(mktemp -d)"
  touch "${test_dir}/pkg1.deb"
  touch "${test_dir}/pkg2.deb"

  rotate_packages "${test_dir}" "*.deb"
  assert_file_exists "${test_dir}/pkg1.deb"
  assert_file_exists "${test_dir}/pkg2.deb"

  rm -rf "${test_dir}"
}

test_generate_repo_rotate_packages_over_limit() {
  local test_dir
  test_dir="$(mktemp -d)"
  local i
  i=1
  while test "${i}" -le 52; do
    touch "${test_dir}/package_v${i}_amd64.deb"
    i=$((i + 1))
  done

  rotate_packages "${test_dir}" "*_amd64.deb"
  assert_file_not_exists "${test_dir}/package_v1_amd64.deb"
  assert_file_not_exists "${test_dir}/package_v2_amd64.deb"
  assert_file_exists "${test_dir}/package_v52_amd64.deb"

  rm -rf "${test_dir}"
}

test_generate_repo_deb_repo_success() {
  local test_dir
  test_dir="$(mktemp -d)"
  local new_pkg_dir
  local output_dir
  local existing_dir
  new_pkg_dir="${test_dir}/new"
  output_dir="${test_dir}/output"
  existing_dir="${test_dir}/existing"
  mkdir -p "${new_pkg_dir}" "${existing_dir}/deb/pool/main"

  touch "${new_pkg_dir}/new_1.0_amd64.deb"
  touch "${existing_dir}/deb/pool/main/old_0.9_amd64.deb"

  (
    dpkg-scanpackages() {
      printf "Package: test\n"
    }
    apt-ftparchive() {
      printf "Origin: test\n"
    }
    sign_detached() {
      test -z "${2:-}" || touch "${2}"
    }
    sign_clearsign() {
      test -z "${2:-}" || touch "${2}"
    }
    generate_deb_repo "${new_pkg_dir}" "${output_dir}" "${existing_dir}"
    dpkg-scanpackages >/dev/null
    apt-ftparchive >/dev/null
    sign_detached "" "" >/dev/null
    sign_clearsign "" "" >/dev/null
  )
  assert_successful_code
  assert_file_exists "${output_dir}/deb/pool/main/new_1.0_amd64.deb"
  assert_file_exists "${output_dir}/deb/pool/main/old_0.9_amd64.deb"
  assert_file_exists "${output_dir}/deb/dists/stable/Release"

  rm -rf "${test_dir}"
}

test_generate_repo_deb_repo_scanpackages_failure() {
  local test_dir
  test_dir="$(mktemp -d)"
  local exit_code
  set +e
  (
    dpkg-scanpackages() {
      return 1
    }
    generate_deb_repo "${test_dir}" "${test_dir}/output"
    dpkg-scanpackages >/dev/null 2>&1
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
  rm -rf "${test_dir}"
}

test_generate_repo_deb_repo_apt_ftparchive_failure() {
  local test_dir
  test_dir="$(mktemp -d)"
  local exit_code
  set +e
  (
    dpkg-scanpackages() {
      printf "Package: test\n"
    }
    apt-ftparchive() {
      return 1
    }
    generate_deb_repo "${test_dir}" "${test_dir}/output"
    dpkg-scanpackages >/dev/null
    apt-ftparchive >/dev/null 2>&1
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
  rm -rf "${test_dir}"
}

test_generate_repo_rpm_repo_success() {
  local test_dir
  test_dir="$(mktemp -d)"
  local new_pkg_dir
  local output_dir
  local existing_dir
  new_pkg_dir="${test_dir}/new"
  output_dir="${test_dir}/output"
  existing_dir="${test_dir}/existing"
  mkdir -p "${new_pkg_dir}" "${existing_dir}/rpm"

  touch "${new_pkg_dir}/new-1.0.x86_64.rpm"
  touch "${existing_dir}/rpm/old-0.9.x86_64.rpm"

  (
    createrepo_c() {
      local dir
      dir="${2:-${1:-}}"
      test -n "${dir}" || return 0
      mkdir -p "${dir}/repodata"
      touch "${dir}/repodata/repomd.xml"
    }
    sign_detached() {
      test -z "${2:-}" || touch "${2}"
    }
    generate_rpm_repo "${new_pkg_dir}" "${output_dir}" "${existing_dir}"
    createrepo_c "" >/dev/null
    sign_detached "" "" >/dev/null
  )
  assert_successful_code
  assert_file_exists "${output_dir}/rpm/new-1.0.x86_64.rpm"
  assert_file_exists "${output_dir}/rpm/old-0.9.x86_64.rpm"
  assert_file_exists "${output_dir}/rpm/repodata/repomd.xml"

  rm -rf "${test_dir}"
}

test_generate_repo_rpm_repo_failure() {
  local test_dir
  test_dir="$(mktemp -d)"
  local exit_code
  set +e
  (
    createrepo_c() {
      return 1
    }
    generate_rpm_repo "${test_dir}" "${test_dir}/output"
    createrepo_c "" >/dev/null 2>&1
  ) >/dev/null 2>&1
  exit_code=$?
  set -e
  assert_equals "1" "${exit_code}"
  rm -rf "${test_dir}"
}

test_generate_repo_main_success() {
  local test_dir
  test_dir="$(mktemp -d)"
  local new_pkg_dir
  local output_dir
  new_pkg_dir="${test_dir}/new"
  output_dir="${test_dir}/output"
  mkdir -p "${new_pkg_dir}"

  (
    check_dependencies() {
      return 0
    }
    import_gpg_key() {
      return 0
    }
    generate_deb_repo() {
      return 0
    }
    generate_rpm_repo() {
      return 0
    }
    main "${new_pkg_dir}" "${output_dir}"
    check_dependencies >/dev/null
    import_gpg_key >/dev/null
    generate_deb_repo "" "" "" >/dev/null
    generate_rpm_repo "" "" "" >/dev/null
  )
  assert_successful_code
  rm -rf "${test_dir}"
}

test_generate_repo_main_trace_enabled() {
  local test_dir
  test_dir="$(mktemp -d)"
  local new_pkg_dir
  local output_dir
  new_pkg_dir="${test_dir}/new"
  output_dir="${test_dir}/output"
  mkdir -p "${new_pkg_dir}"

  local TRACE=1
  (
    check_dependencies() {
      return 0
    }
    import_gpg_key() {
      return 0
    }
    generate_deb_repo() {
      return 0
    }
    generate_rpm_repo() {
      return 0
    }
    main "${new_pkg_dir}" "${output_dir}"
    check_dependencies >/dev/null
    import_gpg_key >/dev/null
    generate_deb_repo "" "" "" >/dev/null
    generate_rpm_repo "" "" "" >/dev/null
  )
  assert_successful_code
  rm -rf "${test_dir}"
}

test_generate_repo_direct_invocation_block() {
  local output
  output="$(
    export BASH_SOURCE_OVERRIDE="./scripts/generate-repo.sh"
    source ./scripts/generate-repo.sh -h
  )"
  assert_contains "Usage:" "${output}"
}

#!/usr/bin/env bash
set -euo pipefail

ORIGIN_NAME="webstudiobond"
LABEL_NAME="crowdsec-cloudflare-list-bouncer"
SUITE_NAME="stable"
CODENAME_NAME="stable"
COMPONENTS_NAME="main"
ARCHITECTURES_NAME="amd64 arm64"
DESCRIPTION_NAME="CrowdSec Cloudflare List Bouncer APT Repository"
KEEP_COUNT=50

die() {
  local message
  message="${1:-Unexpected failure}"
  printf "Error: %s\n" "${message}" >&2
  exit 1
}

usage() {
  printf "Usage: %s [OPTIONS] <NEW_PACKAGES_DIR> <OUTPUT_DIR> [EXISTING_REPO_DIR]\n" "$0"
  printf "Generate and sign Debian (APT) and RedHat (RPM) repositories.\n"
  printf "Options:\n"
  printf "  -h, --help    Display usage instructions\n"
}

cleanup() {
  trap - EXIT INT TERM
}

has_command() {
  local cmd
  cmd="${1:-}"
  case "$(command -v "${cmd}" >/dev/null 2>&1 && printf "yes" || printf "no")" in
  yes)
    printf "yes"
    ;;
  *)
    printf "no"
    ;;
  esac
}

check_dependencies() {
  local missing
  missing=""
  for cmd in gpg dpkg-scanpackages apt-ftparchive gzip createrepo_c; do
    case "$(has_command "${cmd}")" in
    no)
      missing="${missing}${missing:+ }${cmd}"
      ;;
    *)
      ;;
    esac
  done

  test -z "${missing}" || die "Missing required commands: ${missing}"
}

import_gpg_key() {
  test -n "${GPG_PRIVATE_KEY:-}" || die "GPG_PRIVATE_KEY environment variable is required"

  case "${GPG_PASSPHRASE:-}" in
  "")
    printf "%s\n" "${GPG_PRIVATE_KEY}" | gpg --batch --import >/dev/null 2>&1 || die "Failed to import GPG private key"
    ;;
  *)
    printf "%s\n" "${GPG_PRIVATE_KEY}" | gpg --batch --pinentry-mode loopback --passphrase "${GPG_PASSPHRASE}" --import >/dev/null 2>&1 || die "Failed to import GPG private key"
    ;;
  esac
}

sign_detached() {
  local source_file
  local target_sig
  source_file="${1}"
  target_sig="${2}"

  case "${GPG_PASSPHRASE:-}" in
  "")
    gpg --batch --yes --armor --detach-sign --output "${target_sig}" "${source_file}" || die "Failed to create detached signature for ${source_file}"
    ;;
  *)
    gpg --batch --yes --pinentry-mode loopback --passphrase "${GPG_PASSPHRASE}" --armor --detach-sign --output "${target_sig}" "${source_file}" || die "Failed to create detached signature for ${source_file}"
    ;;
  esac
}

sign_clearsign() {
  local source_file
  local target_sig
  source_file="${1}"
  target_sig="${2}"

  case "${GPG_PASSPHRASE:-}" in
  "")
    gpg --batch --yes --clearsign --output "${target_sig}" "${source_file}" || die "Failed to create clearsigned signature for ${source_file}"
    ;;
  *)
    gpg --batch --yes --pinentry-mode loopback --passphrase "${GPG_PASSPHRASE}" --clearsign --output "${target_sig}" "${source_file}" || die "Failed to create clearsigned signature for ${source_file}"
    ;;
  esac
}

rotate_packages() {
  local target_dir
  local pattern
  target_dir="${1}"
  pattern="${2}"

  local files_to_delete
  files_to_delete="$(find "${target_dir}" -maxdepth 1 -type f -name "${pattern}" 2>/dev/null | sort -rV | tail -n "+$((KEEP_COUNT + 1))" || true)"

  case "${files_to_delete}" in
  "")
    ;;
  *)
    printf "%s\n" "${files_to_delete}" | while IFS= read -r file_path; do
      test -z "${file_path}" || rm -f "${file_path}"
    done
    ;;
  esac
}

generate_deb_repo() {
  local new_packages_dir
  local output_dir
  local existing_repo_dir
  new_packages_dir="${1}"
  output_dir="${2}"
  existing_repo_dir="${3:-}"

  local pool_dir
  pool_dir="${output_dir}/deb/pool/main"
  mkdir -p "${pool_dir}"

  case "${existing_repo_dir}" in
  "")
    ;;
  *)
    case "$(test -d "${existing_repo_dir}/deb/pool/main" && printf "yes" || printf "no")" in
    yes)
      find "${existing_repo_dir}/deb/pool/main" -maxdepth 1 -type f -name "*.deb" -exec cp {} "${pool_dir}/" \; 2>/dev/null || true
      ;;
    *)
      ;;
    esac
    ;;
  esac

  find "${new_packages_dir}" -maxdepth 1 -type f -name "*.deb" -exec cp {} "${pool_dir}/" \; 2>/dev/null || true

  rotate_packages "${pool_dir}" "*_amd64.deb"
  rotate_packages "${pool_dir}" "*_arm64.deb"

  local deb_root
  deb_root="${output_dir}/deb"

  for arch in amd64 arm64; do
    local binary_dir
    binary_dir="${deb_root}/dists/${SUITE_NAME}/${COMPONENTS_NAME}/binary-${arch}"
    mkdir -p "${binary_dir}"
    (cd "${deb_root}" && dpkg-scanpackages --arch "${arch}" pool/main /dev/null >"${binary_dir}/Packages") || die "Failed to scan deb packages for ${arch}"
    gzip -9nc "${binary_dir}/Packages" >"${binary_dir}/Packages.gz" || die "Failed to compress Packages index for ${arch}"
  done

  local dist_dir
  dist_dir="${deb_root}/dists/${SUITE_NAME}"
  local config_file
  config_file="${dist_dir}/apt-ftparchive.conf"

  printf "APT::FTPArchive::Release::Origin \"%s\";\nAPT::FTPArchive::Release::Label \"%s\";\nAPT::FTPArchive::Release::Suite \"%s\";\nAPT::FTPArchive::Release::Codename \"%s\";\nAPT::FTPArchive::Release::Architectures \"%s\";\nAPT::FTPArchive::Release::Components \"%s\";\nAPT::FTPArchive::Release::Description \"%s\";\n" \
    "${ORIGIN_NAME}" \
    "${LABEL_NAME}" \
    "${SUITE_NAME}" \
    "${CODENAME_NAME}" \
    "${ARCHITECTURES_NAME}" \
    "${COMPONENTS_NAME}" \
    "${DESCRIPTION_NAME}" >"${config_file}"

  (cd "${dist_dir}" && apt-ftparchive -c "${config_file}" release . >Release) || die "Failed to generate Release file"
  rm -f "${config_file}"

  sign_detached "${dist_dir}/Release" "${dist_dir}/Release.gpg"
  sign_clearsign "${dist_dir}/Release" "${dist_dir}/InRelease"
}

generate_rpm_repo() {
  local new_packages_dir
  local output_dir
  local existing_repo_dir
  new_packages_dir="${1}"
  output_dir="${2}"
  existing_repo_dir="${3:-}"

  local rpm_dir
  rpm_dir="${output_dir}/rpm"
  mkdir -p "${rpm_dir}"

  case "${existing_repo_dir}" in
  "")
    ;;
  *)
    case "$(test -d "${existing_repo_dir}/rpm" && printf "yes" || printf "no")" in
    yes)
      find "${existing_repo_dir}/rpm" -maxdepth 1 -type f -name "*.rpm" -exec cp {} "${rpm_dir}/" \; 2>/dev/null || true
      ;;
    *)
      ;;
    esac
    ;;
  esac

  find "${new_packages_dir}" -maxdepth 1 -type f -name "*.rpm" -exec cp {} "${rpm_dir}/" \; 2>/dev/null || true

  rotate_packages "${rpm_dir}" "*.x86_64.rpm"
  rotate_packages "${rpm_dir}" "*.aarch64.rpm"

  createrepo_c --update "${rpm_dir}" || die "Failed to generate RPM repodata"
  sign_detached "${rpm_dir}/repodata/repomd.xml" "${rpm_dir}/repodata/repomd.xml.asc"
}

main() {
  case "${TRACE:-0}" in
  1)
    set -x
    ;;
  *)
    ;;
  esac

  local first_arg
  first_arg="${1:-}"

  case "${first_arg}" in
  -h | --help)
    usage
    cleanup
    return 0
    ;;
  "")
    usage >&2
    die "Missing required arguments: <NEW_PACKAGES_DIR> <OUTPUT_DIR>"
    ;;
  *)
    ;;
  esac

  local new_packages_dir
  local output_dir
  local existing_repo_dir
  new_packages_dir="${1}"
  output_dir="${2:-}"
  existing_repo_dir="${3:-}"

  test -n "${output_dir}" || die "Missing required argument: <OUTPUT_DIR>"
  test -d "${new_packages_dir}" || die "New packages directory not found: ${new_packages_dir}"

  mkdir -p "${output_dir}"

  check_dependencies
  import_gpg_key

  generate_deb_repo "${new_packages_dir}" "${output_dir}" "${existing_repo_dir}"
  generate_rpm_repo "${new_packages_dir}" "${output_dir}" "${existing_repo_dir}"

  cleanup
  return 0
}

case "${BASH_SOURCE[0]}" in
"${0}" | "${BASH_SOURCE_OVERRIDE:-}")
  trap cleanup EXIT INT TERM
  main "$@"
  ;;
*)
  ;;
esac

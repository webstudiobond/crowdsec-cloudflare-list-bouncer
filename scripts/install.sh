#!/usr/bin/env bash
set -euo pipefail

REPO="webstudiobond/crowdsec-cloudflare-list-bouncer"
BIN_NAME="crowdsec-cloudflare-list-bouncer"

die() {
  local message
  message="${1:-Unexpected failure}"
  printf "Error: %s\n" "${message}" >&2
  exit 1
}

usage() {
  printf "Usage: %s [OPTIONS]\n" "$0"
  printf "Download, verify, and install or update the latest crowdsec-cloudflare-list-bouncer package.\n"
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

check_privileges() {
  case "$(id -u)" in
  0)
    ;;
  *)
    case "$(has_command sudo)" in
    no)
      die "Root privileges or sudo required to run installer"
      ;;
    *)
      ;;
    esac
    ;;
  esac
}

check_dependencies() {
  local missing
  missing=""
  for cmd in curl jq; do
    case "$(has_command "${cmd}")" in
    no)
      missing="${missing}${missing:+ }${cmd}"
      ;;
    *)
      ;;
    esac
  done

  local has_shasum
  has_shasum="no"
  case "$(has_command sha256sum)" in
  yes)
    has_shasum="yes"
    ;;
  *)
    case "$(has_command shasum)" in
    yes)
      has_shasum="yes"
      ;;
    *)
      ;;
    esac
    ;;
  esac

  case "${has_shasum}" in
  no)
    missing="${missing}${missing:+ }sha256sum/shasum"
    ;;
  *)
    ;;
  esac

  test -z "${missing}" || die "Missing required dependencies: ${missing}"
}

detect_arch() {
  local machine
  machine="$(uname -m)"
  case "${machine}" in
  x86_64 | amd64)
    printf "amd64"
    ;;
  aarch64 | arm64)
    printf "arm64"
    ;;
  *)
    die "Unsupported architecture: ${machine}"
    ;;
  esac
}

detect_package_format() {
  local format
  format="unknown"
  case "$(has_command dpkg)" in
  yes)
    format="deb"
    ;;
  *)
    case "$(has_command rpm)" in
    yes)
      format="rpm"
      ;;
    *)
      ;;
    esac
    ;;
  esac

  case "${format}" in
  unknown)
    die "Neither dpkg nor rpm package managers found on system"
    ;;
  *)
    printf "%s" "${format}"
    ;;
  esac
}

get_current_version() {
  local current_version
  current_version="none"
  case "$(has_command "${BIN_NAME}")" in
  yes)
    current_version="$("${BIN_NAME}" -v 2>&1 | awk '{print $NF}' || true)"
    ;;
  *)
    ;;
  esac
  test -n "${current_version}" || current_version="none"
  printf "%s" "${current_version}"
}

verify_checksum() {
  local target_file
  local expected_digest
  target_file="${1}"
  expected_digest="${2}"

  case "${expected_digest}" in
  "" | null)
    die "Checksum verification digest is empty"
    ;;
  *)
    ;;
  esac

  local hasher
  hasher="none"
  case "$(has_command sha256sum)" in
  yes)
    hasher="sha256sum"
    ;;
  *)
    case "$(has_command shasum)" in
    yes)
      hasher="shasum"
      ;;
    *)
      ;;
    esac
    ;;
  esac

  case "${hasher}" in
  sha256sum)
    printf "%s  %s\n" "${expected_digest}" "${target_file}" | sha256sum -c - >/dev/null 2>&1 || die "SHA256 checksum verification failed"
    ;;
  shasum)
    printf "%s  %s\n" "${expected_digest}" "${target_file}" | shasum -a 256 -c - >/dev/null 2>&1 || die "SHA256 checksum verification failed"
    ;;
  *)
    die "No suitable SHA256 verification utility found"
    ;;
  esac
}

run_privileged() {
  case "$(id -u)" in
  0)
    "$@"
    ;;
  *)
    sudo "$@"
    ;;
  esac
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
    ;;
  *)
    die "Invalid argument: ${first_arg}"
    ;;
  esac

  check_privileges

  check_dependencies

  local arch
  local pkg_format
  arch="$(detect_arch)"
  pkg_format="$(detect_package_format)"

  printf "Detected architecture: %s, package format: %s\n" "${arch}" "${pkg_format}"

  local release_json
  release_json="$(curl -fSs "https://api.github.com/repos/${REPO}/releases/latest" || die "Failed to query GitHub Releases API")"

  local latest_version
  latest_version="$(printf "%s" "${release_json}" | jq -r '.tag_name // empty' || true)"
  test -n "${latest_version}" || die "Failed to determine latest release tag"

  local current_version
  current_version="$(get_current_version)"

  printf "Current installed version: %s\n" "${current_version}"
  printf "Latest release version:    %s\n" "${latest_version}"

  local normalized_latest
  normalized_latest="${latest_version#v}"

  case "${current_version}" in
  "${latest_version}" | "${normalized_latest}")
    printf "Already running latest version. No update required.\n"
    cleanup
    return 0
    ;;
  *)
    ;;
  esac

  local asset_name
  asset_name="$(printf "%s" "${release_json}" | jq -r --arg fmt ".${pkg_format}" --arg arch "${arch}" '.assets[] | select((.name | endswith($fmt)) and (.name | contains($arch))) | .name' | head -n 1 || true)"
  test -n "${asset_name}" || die "No matching release asset found for architecture ${arch} and format ${pkg_format}"

  local download_url
  download_url="$(printf "%s" "${release_json}" | jq -r --arg name "${asset_name}" '.assets[] | select(.name == $name) | .browser_download_url' || true)"
  test -n "${download_url}" || die "Failed to obtain download URL for asset ${asset_name}"

  local expected_hash
  expected_hash="$(printf "%s" "${release_json}" | jq -r --arg name "${asset_name}" '.assets[] | select(.name == $name) | .digest // empty' || true)"
  expected_hash="${expected_hash#sha256:}"
  test -n "${expected_hash}" || die "Checksum digest for ${asset_name} is missing from release metadata"

  local tmp_dir
  tmp_dir="$(mktemp -d)" || die "Failed to create temporary directory"
  trap 'rm -rf "${tmp_dir}"' EXIT INT TERM

  local target_path
  target_path="${tmp_dir}/${asset_name}"

  printf "Downloading %s...\n" "${asset_name}"
  curl -fSsL "${download_url}" -o "${target_path}" || die "Failed to download ${asset_name}"

  printf "Verifying SHA256 checksum...\n"
  verify_checksum "${target_path}" "${expected_hash}"
  printf "Checksum verified successfully.\n"

  printf "Installing package...\n"
  case "${pkg_format}" in
  deb)
    run_privileged dpkg -i "${target_path}"
    ;;
  rpm)
    run_privileged rpm -Uvh "${target_path}"
    ;;
  *)
    die "Unsupported package format: ${pkg_format}"
    ;;
  esac

  printf "Successfully installed crowdsec-cloudflare-list-bouncer %s\n" "${latest_version}"
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

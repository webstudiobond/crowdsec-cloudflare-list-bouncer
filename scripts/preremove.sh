#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="crowdsec-cloudflare-list-bouncer.service"
SYSTEMD_RUN_DIR="/run/systemd/system"

die() {
  local message
  message="${1:-Unexpected failure}"
  printf "Error: %s\n" "${message}" >&2
  exit 1
}

usage() {
  printf "Usage: %s [OPTIONS]\n" "$0"
  printf "Pre-removal service de-registration for crowdsec-cloudflare-list-bouncer.\n"
  printf "Options:\n"
  printf "  -h, --help    Display usage instructions\n"
}

cleanup() {
  trap - EXIT INT TERM
}

trap cleanup EXIT INT TERM

check_systemd_active() {
  local active
  active="no"
  test -d "${SYSTEMD_RUN_DIR}" && command -v systemctl >/dev/null 2>&1 && active="yes"
  printf "%s" "${active}"
}

stop_and_disable_service() {
  local systemd_state
  systemd_state="$(check_systemd_active)"
  case "${systemd_state}" in
  yes)
    systemctl disable --now "${SERVICE_NAME}" >/dev/null 2>&1 || true
    ;;
  *)
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
    exit 0
    ;;
  "" | remove | upgrade | deconfigure | failed-upgrade | [0-9]*)
    ;;
  *)
    die "Invalid argument: ${first_arg}"
    ;;
  esac

  stop_and_disable_service
  cleanup
  exit 0
}

main "$@"

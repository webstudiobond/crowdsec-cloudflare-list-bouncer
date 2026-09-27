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
    systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null && systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
    systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null && systemctl disable "${SERVICE_NAME}" >/dev/null 2>&1 || true
    ;;
  *)
    ;;
  esac
}

main() {
  trap cleanup EXIT INT TERM

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
  "" | remove | upgrade | deconfigure | failed-upgrade | [0-9]*)
    ;;
  *)
    die "Invalid argument: ${first_arg}"
    ;;
  esac

  stop_and_disable_service
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

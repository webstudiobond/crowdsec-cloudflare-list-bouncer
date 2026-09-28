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
  printf "Usage: %s [OPTIONS] [ACTION] [OLD_VERSION]\n" "$0"
  printf "Post-installation service registration for crowdsec-cloudflare-list-bouncer.\n"
  printf "Options:\n"
  printf "  -h, --help    Display usage instructions\n"
  printf "Actions:\n"
  printf "  configure     Register and optionally restart the service\n"
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

configure_service() {
  local old_version
  old_version="${1:-}"

  local systemd_state
  systemd_state="$(check_systemd_active)"
  case "${systemd_state}" in
  yes)
    systemctl daemon-reload >/dev/null 2>&1 || true
    local enabled_state
    enabled_state="$(systemctl is-enabled "${SERVICE_NAME}" 2>/dev/null || printf "disabled")"
    case "${enabled_state}" in
    enabled)
      ;;
    *)
      systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
      ;;
    esac
    case "${old_version}" in
    ?*)
      systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
      ;;
    *)
      ;;
    esac
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

  local second_arg
  second_arg="${2:-}"

  case "${first_arg}" in
  -h | --help)
    usage
    cleanup
    return 0
    ;;
  "" | configure)
    configure_service "${second_arg}"
    ;;
  1)
    configure_service ""
    ;;
  [2-9]*)
    configure_service "${first_arg}"
    ;;
  *)
    die "Invalid argument: ${first_arg}"
    ;;
  esac

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

#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="crowdsec-cloudflare-list-bouncer.service"
SYSTEMD_RUN_DIR="/run/systemd/system"
TARGETS_DIR="/etc/crowdsec/bouncers/cloudflare-list-targets.d"
DEFAULTS_FILE="/etc/default/crowdsec-cloudflare-list-bouncer"
MAIN_CONFIG_FILE="/etc/crowdsec/bouncers/crowdsec-cloudflare-list-bouncer.yaml"

die() {
  local message
  message="${1:-Unexpected failure}"
  printf "Error: %s\n" "${message}" >&2
  exit 1
}

usage() {
  printf "Usage: %s [OPTIONS] [ACTION]\n" "$0"
  printf "Post-removal cleanup and systemd daemon reload for crowdsec-cloudflare-list-bouncer.\n"
  printf "Options:\n"
  printf "  -h, --help    Display usage instructions\n"
  printf "Actions:\n"
  printf "  remove        Standard package removal\n"
  printf "  purge         Complete removal including residual configuration directories\n"
  printf "  upgrade       Package upgrade notification\n"
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

reload_systemd() {
  local systemd_state
  systemd_state="$(check_systemd_active)"
  case "${systemd_state}" in
  yes)
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed "${SERVICE_NAME}" >/dev/null 2>&1 || true
    ;;
  *)
    ;;
  esac
}

purge_residual_dirs() {
  test -d "${TARGETS_DIR}" && rm -rf "${TARGETS_DIR}" 2>/dev/null || true
  test -f "${DEFAULTS_FILE}" && rm -f "${DEFAULTS_FILE}" 2>/dev/null || true
  test -f "${MAIN_CONFIG_FILE}" && rm -f "${MAIN_CONFIG_FILE}" 2>/dev/null || true
}

main() {
  case "${TRACE:-0}" in
  1)
    set -x
    ;;
  *)
    ;;
  esac

  local action
  action="${1:-}"

  case "${action}" in
  -h | --help)
    usage
    exit 0
    ;;
  purge)
    reload_systemd
    purge_residual_dirs
    ;;
  remove | upgrade | failed-upgrade | abort-install | abort-upgrade | disappear | [0-9]* | "")
    reload_systemd
    ;;
  *)
    die "Invalid argument: ${action}"
    ;;
  esac

  cleanup
  exit 0
}

case "${BASH_SOURCE[0]}" in
"${0}" | "${BASH_SOURCE_OVERRIDE:-}")
  trap cleanup EXIT INT TERM
  main "$@"
  ;;
*)
  ;;
esac

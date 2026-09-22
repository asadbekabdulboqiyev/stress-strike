#!/usr/bin/env bash
#
# common.sh — small interactive helpers shared by the stress-strike deploy
# scripts. Safe for ordinary users: every question has a default, every step
# is optional, and errors tell you what exactly to install.

# --- Colors (disable when not a TTY) ----------------------------------------
if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_BLU=$'\033[34m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''; C_BLD=''; C_RST=''
fi

log_step()  { echo "${C_BLU}==>${C_RST}${C_BLD} $*${C_RST}"; }
log_info()  { echo "${C_BLU}   $*${C_RST}"; }
log_ok()    { echo "  ${C_GRN}✓${C_RST} $*"; }
log_warn()  { echo "${C_YEL}warning:${C_RST} $*"; }
log_err()   { echo "${C_RED}error:${C_RST} $*" >&2; }

# prompt_var VARNAME "question" "default" — asks and sets VARNAME.
prompt_var() {
  local var="$1" q="$2" dflt="$3"
  local line
  if [[ -n "$dflt" ]]; then
    read -erp "$q [$dflt] " line
  else
    read -erp "$q " line
  fi
  if [[ -z "$line" ]]; then line="$dflt"; fi
  printf -v "$var" '%s' "$line"
}

# prompt_yes_no VARNAME "question" "default(y|n)" — sets VARNAME to y or n.
prompt_yes_no() {
  local var="$1" q="$2" dflt="$3" line
  while true; do
    read -erp "$q (y/n) [$dflt] " line
    line="${line:-$dflt}"
    case "$line" in
      y|Y|yes|YES) printf -v "$var" 'y'; return 0 ;;
      n|N|no|NO)   printf -v "$var" 'n'; return 0 ;;
      *) log_warn "answer 'y' or 'n'"; ;;
    esac
  done
}

# confirm "question" "default(y|n)" — aborts with error when user says no.
confirm() {
  local ans
  prompt_yes_no ans "$1" "$2"
  if [[ "$ans" != "y" ]]; then
    log_err "aborted by user"
    exit 1
  fi
}

# require_cmd CMD [install-hint] — fails with a friendly message if missing.
require_cmd() {
  local cmd="$1" hint="${2:-}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_err "required tool not found: '${cmd}'"
    [[ -n "$hint" ]] && log_info "fix: $hint"
    exit 1
  fi
}

# command_available CMD — 0 if present, 1 otherwise.
command_available() { command -v "$1" >/dev/null 2>&1; }

# detect_remote_arch host user@host:port — returns amd64|arm64 for a remote.
detect_remote_arch() {
  ssh -o ConnectTimeout=8 -o BatchMode=yes "$1" 'uname -m' 2>/dev/null \
    | sed 's/x86_64/amd64/; s/aarch64/arm64/' | tr -d '\r'
}

# banner "title"
banner() {
  echo
  echo "============================================================"
  echo "  $*"
  echo "============================================================"
}
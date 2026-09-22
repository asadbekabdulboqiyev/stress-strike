#!/usr/bin/env bash
#
# deploy.sh — one entry point for running stress-strike fleets. Picks the
# simplest path that works on your machine and walks you through it.
#
#   ./scripts/deploy.sh            # menu (or picks Docker automatically)
#   ./scripts/deploy.sh docker     # force the Docker path
#   ./scripts/deploy.sh fleet      # force the SSH/VPS fleet path
#   ./scripts/deploy.sh down       # stop the Docker fleet if one is up

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=deploy/fleet/common.sh
source "${REPO_ROOT}/deploy/fleet/common.sh"

WANT="${1:-}"

if [[ "$WANT" == "web" || "$WANT" == "local" || "$WANT" == "demo" ]]; then
  exec "${REPO_ROOT}/start.sh"
fi
if [[ "$WANT" == "down" ]]; then
  exec "${REPO_ROOT}/scripts/deploy-docker.sh" down
fi
if [[ "$WANT" == "docker" ]]; then
  exec "${REPO_ROOT}/scripts/deploy-docker.sh"
fi
if [[ "$WANT" == "fleet" ]]; then
  exec "${REPO_ROOT}/scripts/deploy-fleet.sh"
fi
if [[ -n "$WANT" ]]; then
  log_err "unknown command: $1  (use: docker | fleet | down)"
  exit 2
fi

banner "stress-strike deploy"
echo "Two ways to run a real (multi-node) load test:"
echo
echo "  1) Docker  — easiest. Runs master + workers in containers on this"
echo "               machine. Needs Docker Desktop only. No Linux servers."
echo "  2) Fleet   — puts workers on real Linux hosts you can SSH into."
echo "               (a VPS / home server with ssh + root is enough)"
echo

if command_available docker; then
  log_ok "docker: found"
else
  log_warn "docker: not found (option 1 needs Docker Desktop)"
fi
if command_available ssh; then
  log_ok "ssh:   found"
else
  log_warn "ssh: not found"
fi
echo

if command_available docker && ! command_available ssh; then
  log_step "only Docker is available — starting the Docker wizard."
  exec "${REPO_ROOT}/scripts/deploy-docker.sh"
fi

printf "choose: [1] Docker   [2] Fleet   [q] quit   → "
read -r ans
case "$ans" in
  1) exec "${REPO_ROOT}/scripts/deploy-docker.sh" ;;
  2) exec "${REPO_ROOT}/scripts/deploy-fleet.sh" ;;
  q|Q|"") exit 0 ;;
  *) log_err "choose 1, 2 or q" ; exit 2 ;;
esac
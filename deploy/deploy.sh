#!/usr/bin/env bash
#
# Deploy the ZT-next control plane and console.
#
# Usage:
#   ./deploy.sh up       Build and start the stack
#   ./deploy.sh down     Stop the stack
#   ./deploy.sh status   Show what is running
#   ./deploy.sh logs     Follow the logs
#   ./deploy.sh check    Verify the deployment
#   ./deploy.sh rebuild  Rebuild the images and restart
#
# The stack is three services: the controller, the console's static bundle,
# and Caddy in front of both. The controller is not published to the host;
# only Caddy is, and Caddy terminates TLS.

set -euo pipefail

cd "$(dirname "$0")"

COMPOSE="docker compose"
ENV_FILE=".env"

# Load the environment.
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ENV_FILE"
  set +a
fi

require_env() {
  if [[ -z "${!1:-}" ]]; then
    echo "error: $1 is required. Set it in $ENV_FILE." >&2
    exit 1
  fi
}

compose() {
  $COMPOSE "$@"
}

case "${1:-up}" in
  up)
    require_env ZT_PUBLIC_HOST
    require_env ACME_EMAIL
    echo "==> Building the images"
    compose build
    echo "==> Starting the stack"
    compose up -d
    echo
    echo "The console is at https://${ZT_PUBLIC_HOST}"
    echo "Run './deploy.sh check' to verify it."
    ;;

  down)
    compose down
    ;;

  rebuild)
    require_env ZT_PUBLIC_HOST
    echo "==> Rebuilding the images"
    compose build --no-cache
    echo "==> Restarting the stack"
    compose up -d --force-recreate
    ;;

  status)
    compose ps
    ;;

  logs)
    compose logs -f --tail=100
    ;;

  check)
    require_env ZT_PUBLIC_HOST
    host="https://${ZT_PUBLIC_HOST}"

    echo "==> Health check"
    curl -fsS "${host}/api/v1/health" | head -c 200
    echo

    echo
    echo "==> The API requires a token"
    status=$(curl -s -o /dev/null -w '%{http_code}' "${host}/api/v1/tenants")
    if [[ "$status" == "401" ]]; then
      echo "ok: the master console refuses an unauthenticated request"
    else
      echo "FAIL: expected 401, got $status" >&2
      exit 1
    fi

    echo
    echo "==> The console is served"
    status=$(curl -s -o /dev/null -w '%{http_code}' "${host}/")
    if [[ "$status" == "200" ]]; then
      echo "ok: the console loads"
    else
      echo "FAIL: expected 200, got $status" >&2
      exit 1
    fi
    ;;

  *)
    echo "usage: $0 {up|down|rebuild|status|logs|check}" >&2
    exit 1
    ;;
esac

#!/usr/bin/env bash
# QubitCoin explorer helper — thin wrapper around docker compose profiles.
#
# Usage:
#   ./scripts/explorer.sh regtest up -d
#   ./scripts/explorer.sh testnet4 up -d
#   ./scripts/explorer.sh testnet4 down
#   ./scripts/explorer.sh testnet4 logs -f
#   ./scripts/explorer.sh testnet4 build
#
# Networks: regtest | testnet3 | testnet4 | mainnet

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPLORER_DIR="$(dirname "$SCRIPT_DIR")"
cd "$EXPLORER_DIR"

NETWORK="${1:-}"
ACTION="${2:-up}"
EXTRA=()
if [[ $# -ge 2 ]]; then
	shift 2
	EXTRA=("$@")
elif [[ $# -eq 1 ]]; then
	shift 1
fi

valid_networks="regtest testnet3 testnet4 mainnet"

usage() {
	echo "Usage: $0 <network> [action] [docker compose args...]"
	echo ""
	echo "Networks: $valid_networks"
	echo "Default action: up"
	echo ""
	echo "Examples:"
	echo "  $0 regtest up -d"
	echo "  $0 testnet4 up -d"
	echo "  $0 testnet4 down"
	echo "  $0 testnet4 logs -f"
}

if [[ -z "$NETWORK" ]]; then
	usage
	exit 1
fi

case " $valid_networks " in
	*" $NETWORK "*) ;;
	*)
		echo "Unknown network: $NETWORK"
		echo "Valid: $valid_networks"
		exit 1
		;;
esac

SERVICE="explorer-${NETWORK}"

echo "==> QubitCoin explorer: network=$NETWORK service=$SERVICE action=$ACTION"

docker compose --profile "$NETWORK" "$ACTION" "$SERVICE" "${EXTRA[@]}"

if [[ "$ACTION" == "up" ]]; then
	case "$NETWORK" in
		regtest)    PORT="${REGTEST_EXPLORER_PORT:-3002}" ;;
		testnet3)   PORT="${TESTNET3_EXPLORER_PORT:-3003}" ;;
		testnet4)   PORT="${TESTNET4_EXPLORER_PORT:-3004}" ;;
		mainnet)    PORT="${MAINNET_EXPLORER_PORT:-3005}" ;;
	esac
	echo ""
	echo "Explorer UI: http://127.0.0.1:${PORT}"
	echo "Ensure qbitcoind is running on the matching network with server=1 enabled."
fi

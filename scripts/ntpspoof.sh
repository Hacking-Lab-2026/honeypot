#!/usr/bin/env bash
set -euo pipefail

# ntpspoof.sh
# Multi-source spoof test wrapper: multiple source IPs sending to one victim.

BASE="127.0.0."
START=2
COUNT=50
PER_SOURCE=1
VICTIM="127.0.0.1"
PORT=123
INTERVAL=0.01
REPEAT=1
PY_SCRIPT="scripts/spoof_same_ip.py"

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --base PREFIX     source IP prefix (default ${BASE})
  --start N         first suffix to append (default ${START})
  --count N         number of distinct source IPs (default ${COUNT})
  --per-source N    packets per source IP (default ${PER_SOURCE})
  --victim IP       destination IP (default ${VICTIM})
  --port PORT     destination port (default ${PORT})
  --interval S    seconds between packets (default ${INTERVAL})
  --repeat N      repeat the full set N times (default ${REPEAT})
  -h|--help       show this help

Example:
  sudo $0 --base 127.0.0. --start 2 --count 50 --per-source 30 --victim 127.0.0.1

EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base) BASE="$2"; shift 2;;
    --start) START="$2"; shift 2;;
    --count) COUNT="$2"; shift 2;;
    --per-source) PER_SOURCE="$2"; shift 2;;
    --victim) VICTIM="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --interval) INTERVAL="$2"; shift 2;;
    --repeat) REPEAT="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

if [[ ! -f "$PY_SCRIPT" ]]; then
  echo "Python script $PY_SCRIPT not found. Exiting." >&2
  exit 1
fi

SUDO=""
if [[ $(id -u) -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO=sudo
  else
    echo "This script needs root to add loopback aliases. Install sudo or run as root." >&2
    exit 1
  fi
fi

cleanup() {
  echo "Cleaning up aliases..."
  for i in $(seq 0 $((COUNT-1))); do
    idx=$((START + i))
    ip="${BASE}${idx}"
    $SUDO ip addr del "${ip}/8" dev lo || true
  done
}
trap cleanup EXIT INT TERM

echo "Creating ${COUNT} loopback aliases starting at ${BASE}${START}..."
for i in $(seq 0 $((COUNT-1))); do
  idx=$((START + i))
  ip="${BASE}${idx}"
  echo "Adding alias ${ip}..."
  $SUDO ip addr add "${ip}/8" dev lo || echo "alias ${ip} may already exist"
done

echo "Running $PY_SCRIPT in multi-source mode: base=$BASE start=$START count=$COUNT per-source=$PER_SOURCE victim=$VICTIM"
if [[ $(id -u) -ne 0 ]]; then
  $SUDO python3 "$PY_SCRIPT" --base "$BASE" --start "$START" --count "$COUNT" --per-source "$PER_SOURCE" --victim "$VICTIM" --port "$PORT" --interval "$INTERVAL" --repeat "$REPEAT"
else
  python3 "$PY_SCRIPT" --base "$BASE" --start "$START" --count "$COUNT" --per-source "$PER_SOURCE" --victim "$VICTIM" --port "$PORT" --interval "$INTERVAL" --repeat "$REPEAT"
fi

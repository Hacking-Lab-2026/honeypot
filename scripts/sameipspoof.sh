#!/usr/bin/env bash
set -euo pipefail

# sameipspoof.sh
# Distributed spoof test wrapper: multiple concurrent workers, same spoofed source IP.

SPOOF="127.0.0.55"
VICTIM="127.0.0.1"
PORT=123
WORKERS=10
COUNT=30
INTERVAL=0.01
PY_SCRIPT="scripts/spoof_same_ip.py"

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --spoof IP        spoofed source IP to use (default ${SPOOF})
  --victim IP       destination IP (default ${VICTIM})
  --port PORT       destination port (default ${PORT})
  --workers N       number of concurrent workers (default ${WORKERS})
  --count N         packets per worker (default ${COUNT})
  --interval S      seconds between packets (default ${INTERVAL})
  -h|--help         show this help

Example:
  sudo $0 --spoof 127.0.0.55 --victim 127.0.0.1 --workers 10 --count 30

EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --spoof) SPOOF="$2"; shift 2;;
    --victim) VICTIM="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --workers) WORKERS="$2"; shift 2;;
    --count) COUNT="$2"; shift 2;;
    --interval) INTERVAL="$2"; shift 2;;
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
    echo "This script needs root to send spoofed packets. Install sudo or run as root." >&2
    exit 1
  fi
fi

if [[ $(id -u) -ne 0 ]]; then
  echo "Running $WORKERS workers, all spoofing $SPOOF -> $VICTIM"
else
  echo "Running $WORKERS workers, all spoofing $SPOOF -> $VICTIM"
fi

pids=()
for i in $(seq 1 "$WORKERS"); do
  echo "Starting worker $i/$WORKERS..."
  if [[ $(id -u) -ne 0 ]]; then
    $SUDO python3 "$PY_SCRIPT" --spoof "$SPOOF" --dst "$VICTIM" --port "$PORT" --count "$COUNT" --interval "$INTERVAL" &
  else
    python3 "$PY_SCRIPT" --spoof "$SPOOF" --dst "$VICTIM" --port "$PORT" --count "$COUNT" --interval "$INTERVAL" &
  fi
  pids+=("$!")
done

trap 'for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done' INT TERM

for pid in "${pids[@]}"; do
  wait "$pid"
done

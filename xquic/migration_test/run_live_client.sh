#!/usr/bin/env bash
set -euo pipefail
shopt -s lastpipe
CLEANED=0


IFACE=${IFACE:-enp6s20}       #set your NIC
ADDR=${ADDR:-192.168.68.125}  #set your server IP to connect to

# Resolve repo root from build/tests
ROOT_DIR=$(cd "$(dirname "$0")"/../.. && pwd)
SWITCHER="$ROOT_DIR/migration_test/ip_change.sh"
SWITCH_LOG="$(pwd)/migration_switch.log"
SWITCH_PIDFILE="$(pwd)/switcher.pid"



stop_switcher_force() {
  # Try to stop a running switcher using pidfile or process match
  local pid pgid
  if [ -s "$SWITCH_PIDFILE" ]; then
    pid=$(cat "$SWITCH_PIDFILE" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      pgid=$(ps -o pgid= -p "$pid" | tr -d ' ' || true)
      # Send TERM to the whole process group; use -- to avoid option confusion
      if [ -n "${pgid:-}" ]; then
        sudo kill -TERM -- -"$pgid" 2>/dev/null || true
      else
        sudo kill -TERM -- -"$pid" 2>/dev/null || true
      fi
      sleep 0.2
      if kill -0 "$pid" 2>/dev/null; then
        if [ -n "${pgid:-}" ]; then
          sudo kill -KILL -- -"$pgid" 2>/dev/null || true
        else
          sudo kill -KILL -- -"$pid" 2>/dev/null || true
        fi
      fi
      wait "$pid" 2>/dev/null || true
    fi
  fi
  # Fallback: kill any processes matching the switcher path
  local tries=0
  while true; do
    pids=$(pgrep -f "$SWITCHER" 2>/dev/null || true)
    if [ -z "$pids" ]; then break; fi
    for p in $pids; do
      pgid=$(ps -o pgid= -p "$p" | tr -d ' ' || true)
      sudo kill -TERM -- -"$pgid" 2>/dev/null || true
    done
    sleep 0.2
    pids=$(pgrep -f "$SWITCHER" 2>/dev/null || true)
    if [ -z "$pids" ]; then break; fi
    for p in $pids; do
      pgid=$(ps -o pgid= -p "$p" | tr -d ' ' || true)
      sudo kill -KILL -- -"$pgid" 2>/dev/null || true
    done
    tries=$((tries+1))
    if [ "$tries" -ge 5 ]; then break; fi
  done
  : > "$SWITCH_PIDFILE"
}

start_switcher() {
  # if [ ! -x "$SWITCHER" ]; then
  #   echo "Switch script not executable: $SWITCHER" >&2
  # fi
  # Ensure no previous switcher instance is running
  stop_switcher_force
  #echo "[runner] starting IP switcher: $SWITCHER" >&2
  # Run with sudo as it requires tc/ip privileges; logs to file
  : >"$SWITCH_PIDFILE"
  sudo -E env PIDFILE="$SWITCH_PIDFILE" setsid bash "$SWITCHER" >"$SWITCH_LOG" 2>&1 &
  SWITCH_LAUNCH_PID=$!
  # Wait briefly for the switcher to write its real PID
  for _ in $(seq 1 20); do
    if [ -s "$SWITCH_PIDFILE" ]; then
      SWITCH_PID=$(cat "$SWITCH_PIDFILE")
      break
    fi
    sleep 0.1
  done
  # Fallback: if pidfile missing, try to discover by command match
  if [ -z "${SWITCH_PID:-}" ]; then
    SWITCH_PID=$(pgrep -f "$SWITCHER" | head -n1 || true)
  fi
  # Derive process group id for setsid-started script
  if [ -n "${SWITCH_PID:-}" ]; then
    SWITCH_PGID=$(ps -o pgid= -p "$SWITCH_PID" | tr -d ' ' || true)
  else
    SWITCH_PGID=""
  fi
  #echo "[runner] switcher pid=$SWITCH_PID pgid=${SWITCH_PGID:-unknown}, log=$SWITCH_LOG" >&2
  echo "[runner] tailing switcher log…" >&2
  tail -F "$SWITCH_LOG" >&2 &
  TAIL_PID=$!
  # brief warm-up so rules are in place before connecting
  sleep 1
}

cleanup() {
  local code=$?
  # prevent re-entry and disable traps
  trap - INT TERM QUIT EXIT TSTP
  if [ "$CLEANED" -eq 1 ]; then
    exit $code
  fi
  CLEANED=1
  echo "[runner] stopping switcher (if any)" >&2
  stop_switcher_force
  if [ -n "${TAIL_PID:-}" ] && kill -0 "$TAIL_PID" 2>/dev/null; then
    kill "$TAIL_PID" 2>/dev/null || true
    wait "$TAIL_PID" 2>/dev/null || true
  fi
  # kill all child processes (pipeline etc.) spawned by this script
  pkill -P $$ 2>/dev/null || true
  exit $code
}

trap cleanup INT TERM QUIT EXIT
# Handle Ctrl+Z as terminate
trap 'cleanup' TSTP

start_switcher

echo "[runner] using interface for migration: $IFACE" >&2
./live_client -a "$ADDR" -p 8443 -u /live -3 -l e -c b -m -L -i "$IFACE" 2>client_live.log | \
ffmpeg -hide_banner -loglevel info \
  -fflags nobuffer -flags low_delay \
  -analyzeduration 1000000 -probesize 1000000 \
  -f mpegts -i pipe:0 -vf showinfo -an -f null - 2>&1 | \
python3 -u -c "import sys,time; 
start=time.monotonic_ns()
for line in sys.stdin:
    ms=(time.monotonic_ns()-start)/1e6
    sys.stdout.write(f'{ms:12.3f}ms {line}') " \
> decode_ts.log
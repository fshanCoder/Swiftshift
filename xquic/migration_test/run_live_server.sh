#!/bin/bash
set -euo pipefail

ADDR=${ADDR:-192.168.68.125}
PORT=${PORT:-8443}
INPUT=${INPUT:-test.mp4}
PROFILE=${PROFILE:-call}   # call | game | vr
LOG=${LOG:-server_live.log}
DURATION=${DURATION:-35}    # seconds to stream before stopping (optional)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LIVE_SERVER="$SCRIPT_DIR/../build/tests/live_server" 

# Simple CLI parsing for --duration/-d (overrides env DURATION if provided)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration|-d)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 1; }
      DURATION="$2"; shift 2 ;;
    --)
      shift; break ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 [--duration SECONDS]" >&2
      exit 1 ;;
  esac
done

# Validate DURATION if provided
duration_opt=()
if [[ -n "${DURATION}" ]]; then
  if [[ ! "${DURATION}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "Invalid DURATION='${DURATION}' (must be a positive number)" >&2
    exit 1
  fi
  duration_opt=(-t "${DURATION}")
fi

rm -f "$LOG"

common_video=(
  -re -i "$INPUT"
  -c:v libx264 -preset veryfast -tune zerolatency
  -bf 0 -pix_fmt yuv420p
)

common_mux=(
  -f mpegts -mpegts_flags resend_headers pipe:1
)

# Default: include audio for "call", drop for others (optional, can keep all if you prefer)
audio_call=(-c:a aac -b:a 96k -ar 48000)
audio_none=(-an)

case "$PROFILE" in
  call)
    # Video-call-like: stable frame sizes, fixed GOP, CBR-ish, small VBV (less burst)
    vf=(-vf fps=30)
    x264p=(-g 60 -keyint_min 60 -sc_threshold 0)
    rc=(-b:v 1500k -maxrate 1500k -bufsize 750k)   # small VBV for tight, stable rate
    audio=("${audio_call[@]}")
    ;;
  game)
    # Cloud-gaming-like: more bursty (scene-cut enabled + larger VBV), occasional I-frame spikes
    vf=(-vf fps=60)
    x264p=(-g 120 -keyint_min 1 -sc_threshold 40)  # allow scenecut I-frames (bursts)
    rc=(-b:v 6M -maxrate 18M -bufsize 12M)          # larger VBV allows short-term peaks
    audio=("${audio_none[@]}")
    ;;
  vr)
    # VR/XR-like: higher cadence + tighter buffering + finer slicing (smaller chunks)
    vf=(-vf fps=90)
    x264p=(-g 90 -keyint_min 90 -sc_threshold 0) #-x264-params "slice-max-size=1200")
    rc=(-b:v 10M -maxrate 12M -bufsize 2M)          # tighter VBV to reflect tight latency slack
    audio=("${audio_none[@]}")
    ;;
  *)
    echo "Unknown PROFILE=$PROFILE (use call|game|vr)" >&2
    exit 1
    ;;
esac

TARGET_DIR="$SCRIPT_DIR/../build/tests"
LOG_PATH="$SCRIPT_DIR/$LOG"

ffmpeg \
  "${common_video[@]}" \
  "${vf[@]}" \
  "${x264p[@]}" \
  "${rc[@]}" \
  "${duration_opt[@]}" \
  "${audio[@]}" \
  "${common_mux[@]}" | \
( cd "$TARGET_DIR" && ./live_server -a "$ADDR" -p "$PORT" -z -l e -D -2 2>"$LOG_PATH" )

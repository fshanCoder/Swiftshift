# SwiftShift: Accelerating QUIC Migration for Ultra-Low-Latency Interactive Media

> Research artifact for **SwiftShift**, a QUIC migration optimization framework designed for **ultra-low-latency (ULL) interactive media** (video conferencing, cloud gaming, XR/VR), where even sub-second delivery gaps can cause visible freezes.

**SwiftShift** targets the two dominant sources of migration micro-stalls:
- **RTT-bound blocking path validation**
- **PTO / timeout-amplified loss recovery** around access-network transitions (e.g., Wi-Fi ↔ cellular, NAT rebinding)

---

## TL;DR

SwiftShift integrates two complementary mechanisms:

- **NBV (Non-Blocking Validation)**  
  Overlaps QUIC path validation with *strictly bounded* speculative transmission on a tentative path, eliminating the classic “wait one RTT” blackout—while preserving anti-amplification safety goals.

- **MAPR (Migration-Aware Proactive Retransmission)**  
  Immediately repairs likely-lost **in-flight** packets after a path change and resets loss-detection timers to avoid waiting for stale pre-migration PTO baselines.

In our end-to-end ULL streaming evaluation, SwiftShift:
- reduces **migration-induced stall time** by ~**61%**
- reduces **retransmission overhead** by ~**51%**
- maintains **jitter-buffer stability** under a tight **100 ms** playout-delay budget (no network-side changes required)


## Why this matters

ULL interactive media is unusually sensitive to brief delivery gaps:
- A “small” 200–300 ms transport stall can translate into **frame deadline misses**, **decoder starvation**, and **user-visible freezes**.
- Heterogeneous access networks (Wi-Fi/5G/satellite) make **path changes a routine event** rather than an exception.

SwiftShift treats migration not as a rare corner case, but as a **first-order impairment** for ULL continuity.

---

## Design at a glance

### 1) NBV: bounded speculation during validation
Standard QUIC migration typically blocks full use of a new path until it receives `PATH_RESPONSE`.  
NBV instead:
- marks the new path as **Tentative**
- runs validation in the background
- allows immediate sending on the tentative path within a conservative envelope  
  (charged to anti-amplification accounting; capped by a configurable upper bound)

If validation fails or times out, NBV **rolls back** cleanly by abandoning the tentative path and retransmitting on the last confirmed path.

### 2) MAPR: proactive repair after a switch
MAPR is invoked when the peer’s new address tuple is observed:
1. scan send buffer for **unacknowledged in-flight** packets
2. **immediately retransmit** them on the new path (still respecting the same envelope before confirmation)
3. reset/re-arm the **loss-detection timer** so post-migration recovery reflects the new path’s RTT

---

## Implementation notes

- Implemented on **XQUIC** (wire-compatible; no network-side changes).
- Works for **client-initiated path changes** (common for mobile endpoints).

---

## What’s in this repo (suggested layout)

> Adjust paths/names below to match your actual repository structure.

- `test_client.c` / `test_server.c`  
  Minimal client/server programs used for migration experiments.
- `ffmpeg_server.sh`  
  Example pipeline that feeds MPEG-TS into the QUIC server.
- `ffmpeg_test_vmaf.sh` (optional)  
  Helper for post-processing / quality analysis workflows.

---

## Usage

> **You said you’ll fill this section in.**  
> Suggested structure:
> - Build / dependencies
> - Quick start (server, client)
> - Network emulation / migration trigger
> - How to reproduce each figure/table from the paper

---

## Reproducing the paper’s evaluation (outline)

If you want readers to reproduce results smoothly, consider documenting:

- **Workload profiles (ULL primitives)**
  - video call: 30 FPS, stable pacing, small VBV
  - cloud gaming: 60 FPS, burstier frames, scenecut-enabled keyframes
  - XR/VR: 90 FPS, tighter delivery slack

- **Network dynamics**
  - delay/loss via `tc netem`
  - short blackout around the switch
  - controlled pre-/post-switch conditions (optional) for attribution

- **Metrics**
  - per-migration stall time (excess inter-frame gap)
  - retransmitted packets per migration
  - receiver jitter-buffer slack (e.g., 100 ms target delay)

---


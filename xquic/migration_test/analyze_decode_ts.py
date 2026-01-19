#!/usr/bin/env python3
import re
import sys
import statistics
import argparse
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict

# Allow optional unit suffix after wall timestamp (e.g., "12085.727ms ")
# Example line:
# 12089.067ms [Parsed_showinfo_0 ...] n:   0 pts: 180000 pts_time:2 ...
SHOWINFO_RE = re.compile(
    r"^\s*(?P<ts>\d+(?:\.\d+)?)(?P<unit>ms|s)?\s+.*?\[Parsed_showinfo_0 .*?\] "
    r"n:\s*(?P<n>\d+)\s+pts:\s*(?P<pts>\d+)\s+pts_time:(?P<pts_time>[0-9.]+)\s+"
    r"duration:\s*(?P<dur>\d+)\s+duration_time:(?P<dur_time>[0-9.]+).*?"
    r"i:(?P<i_key>[A-Z])\s+iskey:(?P<iskey>\d)\s+type:(?P<type>[A-Z])"
)

# Frame rate line (with optional leading wall timestamp)
FRAMERATE_RE = re.compile(
    r"^\s*(?:\d+(?:\.\d+)?(?:ms|s)?\s+)? .*?config in time_base: .*? frame_rate:\s*(?P<num>\d+)/(?:\s*(?P<den>\d+))"
)

# Inline event lines within decode_ts.log (prefixed by our timestamp)
EVENT_INLINE_RE = re.compile(r"^\s*(?P<ts>\d+(?:\.\d+)?)(?P<unit>ms|s)?\s+\[EVENT\]\s+IP_SWITCH\b")

@dataclass
class Frame:
    wall_ts: float
    n: int
    pts_time: float
    dur_time: float
    type: str
    is_key: bool
    line_no: int

@dataclass
class Gap:
    idx: int
    dt_wall: float
    dt_pts: float
    excess: float


def _to_seconds(value: str, unit: Optional[str]) -> float:
    v = float(value)
    if unit == 'ms':
        return v / 1000.0
    # treat None or 's' as seconds
    return v


def parse_log(path: str) -> Tuple[Optional[float], List[Frame]]:
    frames: List[Frame] = []
    target_fps: Optional[float] = None
    with open(path, 'r', errors='ignore') as f:
        for idx, line in enumerate(f, start=1):
            m_rate = FRAMERATE_RE.search(line)
            if m_rate and target_fps is None:
                num = int(m_rate.group('num'))
                den = int(m_rate.group('den') or '1')
                if den != 0:
                    target_fps = num / den
            m = SHOWINFO_RE.search(line)
            if not m:
                continue
            wall_ts = _to_seconds(m.group('ts'), m.group('unit'))
            n = int(m.group('n'))
            pts_time = float(m.group('pts_time'))
            dur_time = float(m.group('dur_time'))
            ftype = m.group('type')
            is_key = m.group('iskey') == '1'
            frames.append(Frame(wall_ts, n, pts_time, dur_time, ftype, is_key, idx))
    return target_fps, frames


def analyze(
    frames: List[Frame],
    target_fps: Optional[float],
    stutter_threshold_s: Optional[float] = None,
    events: Optional[List[float]] = None,
    event_pre_window_s: float = 0.2,
    event_post_window_s: float = 2.0,
    excess_mode: str = "pts",  # 'pts' or 'fps'
):
    if len(frames) < 2:
        print("Not enough frames to analyze.")
        return

    # Estimate fps if not provided
    if target_fps is None:
        # Use median pts delta
        deltas = [frames[i].pts_time - frames[i-1].pts_time for i in range(1, len(frames))]
        median_dt = statistics.median(deltas) if deltas else 1/30
        target_fps = 1.0 / median_dt if median_dt > 0 else 30.0

    expected_dt = 1.0 / target_fps
    if stutter_threshold_s is None:
        stutter_threshold_s = max(0.2, 1 * expected_dt)  # >=100ms or >=2 frames worth

    gaps: List[Gap] = []
    max_gap = 0.0
    total_freeze = 0.0

    # Drift = (wall-wall0) - (pts-pts0), tracks realtime lag vs media clock
    drift0 = frames[0].wall_ts - frames[0].pts_time
    drift_values = []

    missing_frames = 0
    for i in range(1, len(frames)):
        dt_wall = frames[i].wall_ts - frames[i-1].wall_ts
        dt_pts  = frames[i].pts_time - frames[i-1].pts_time
        baseline_dt = expected_dt if excess_mode == "fps" else dt_pts
        # detect jumps in decoded frame index
        if frames[i].n != frames[i-1].n + 1:
            missing_frames += (frames[i].n - frames[i-1].n - 1)
        drift = (frames[i].wall_ts - frames[0].wall_ts) - (frames[i].pts_time - frames[0].pts_time)
        drift_values.append(drift)

        if dt_wall > max_gap:
            max_gap = dt_wall
        excess = dt_wall - baseline_dt
        if excess >= stutter_threshold_s:
            total_freeze += excess
            gaps.append(Gap(i, dt_wall, dt_pts, excess))

    wall_span = frames[-1].wall_ts - frames[0].wall_ts
    eff_fps = (len(frames) - 1) / wall_span if wall_span > 0 else 0.0

    p95_gap = 0.0
    wall_gaps = sorted([frames[i].wall_ts - frames[i-1].wall_ts for i in range(1, len(frames))])
    if wall_gaps:
        p95_gap = wall_gaps[int(0.95 * (len(wall_gaps)-1))]

    print("=== Realtime Stutter Analysis ===")
    print(f"Frames: {len(frames)} | Target FPS: {target_fps:.3f} | Expected dt: {expected_dt*1000:.1f} ms")
    print(f"Wall span: {wall_span:.3f} s | Effective FPS: {eff_fps:.2f}")
    print(f"Max inter-frame wall gap: {max_gap*1000:.1f} ms | P95 gap: {p95_gap*1000:.1f} ms")
    print(f"Stutter threshold: {stutter_threshold_s*1000:.1f} ms | Baseline: {excess_mode} | Freeze events: {len(gaps)} | Total freeze: {total_freeze:.3f} s")
    if missing_frames:
        print(f"Missing decoded frames (by n:): {missing_frames}")
    if drift_values:
        print(f"Drift (wall - media): min {min(drift_values):.3f}s, max {max(drift_values):.3f}s, last {drift_values[-1]:.3f}s")

    if gaps:
        print("\nTop 20 largest freezes:")
        gaps_sorted = sorted(gaps, key=lambda g: g.excess, reverse=True)[:20]
        for g in gaps_sorted:
            fr = frames[g.idx]
            prev = frames[g.idx-1]
            base_str = f"exp_dt={expected_dt*1000:.1f}ms" if excess_mode == "fps" else f"pts_dt={g.dt_pts*1000:.1f}ms"
            print(
                f"  n={fr.n} wall_dt={g.dt_wall*1000:.1f}ms {base_str} excess={g.excess*1000:.1f}ms "
                f"at wall={fr.wall_ts:.3f}s pts={fr.pts_time:.3f}s type={fr.type} src_line={fr.line_no}"
            )

    # Correlate freezes with IP switch events if provided
    if events:
        # For each gap, attribute to the nearest preceding event within post window,
        # allowing a small pre window in case the event happens slightly after pause begins.
        events_sorted = sorted(events)
        by_event: Dict[float, List[Gap]] = {e: [] for e in events_sorted}
        in_window_total = 0.0
        out_window_total = 0.0

        ev_idx = 0
        for g in gaps:
            end_ts = frames[g.idx].wall_ts
            start_ts = frames[g.idx-1].wall_ts
            # advance event index to the last event not after the gap end
            while ev_idx + 1 < len(events_sorted) and events_sorted[ev_idx + 1] <= end_ts:
                ev_idx += 1

            assigned = False
            # try current and previous one (handles event slightly after start_ts too)
            for k in (ev_idx, ev_idx - 1):
                if 0 <= k < len(events_sorted):
                    e = events_sorted[k]
                    if (start_ts - event_pre_window_s) <= e <= (end_ts + event_post_window_s):
                        by_event[e].append(g)
                        in_window_total += g.excess
                        assigned = True
                        break
            if not assigned:
                out_window_total += g.excess

        print("\n=== Event Correlation (IP Switch) ===")
        print(f"Attribution window: pre {event_pre_window_s*1000:.0f} ms, post {event_post_window_s*1000:.0f} ms")
        print(f"Freeze near events: {in_window_total:.3f}s | Outside: {out_window_total:.3f}s")

        for e in events_sorted:
            gl = by_event.get(e, [])
            if not gl:
                print(f"  Event at {e:.3f}s: no freeze detected in window")
                continue
            total = sum(x.excess for x in gl)
            m = max(gl, key=lambda x: x.excess)
            fr = frames[m.idx]
            print(
                f"  Event at {e:.3f}s: freezes={len(gl)} total={total:.3f}s max={m.excess*1000:.0f}ms "
                f"(peak frame n={fr.n} at {fr.wall_ts:.3f}s)"
            )


def parse_events(path: str) -> List[float]:
    # Accept one event per line. Supports values like "12.345", "12345ms", "12.3 s".
    EV_RE = re.compile(r"^\s*(?P<v>\d+(?:\.\d+)?)(?:\s*(?P<u>ms|s))?\b")
    out: List[float] = []
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            m = EV_RE.search(line)
            if not m:
                continue
            out.append(_to_seconds(m.group('v'), m.group('u')))
    return out


def parse_events_inline(path: str) -> List[float]:
    out: List[float] = []
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            m = EVENT_INLINE_RE.search(line)
            if not m:
                continue
            out.append(_to_seconds(m.group('ts'), m.group('unit')))
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Analyze ffmpeg showinfo logs for realtime stutter and correlate with IP switch events."
    )
    parser.add_argument("log", help="Path to decode_ts.log (showinfo output with wall timestamps)")
    parser.add_argument("--stutter-ms", type=float, default=None, help="Freeze threshold in ms (default: max(100ms, 2*frame))")
    parser.add_argument("--events", help="Path to events log (one timestamp per line, seconds or ms)")
    parser.add_argument("--pre", type=float, default=0.2, help="Pre-event window in seconds (default 0.2s)")
    parser.add_argument("--post", type=float, default=2.0, help="Post-event window in seconds (default 2.0s)")
    parser.add_argument("--excess-mode", choices=["pts", "fps"], default="pts",
                        help="Excess baseline: 'pts' (use PTS delta) or 'fps' (use expected 1/fps). Default 'pts'.")
    parser.add_argument("--events-inline", action="store_true",
                        help="Parse IP switch [EVENT] markers directly from the provided log file.")

    args = parser.parse_args()

    target_fps, frames = parse_log(args.log)
    st_s = (args.stutter_ms / 1000.0) if args.stutter_ms is not None else None
    events = None
    if args.events_inline:
        events = parse_events_inline(args.log)
    elif args.events:
        events = parse_events(args.events)
    analyze(frames, target_fps, st_s, events, args.pre, args.post, args.excess_mode)

if __name__ == '__main__':
    main()

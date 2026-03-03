# SwiftShift: Accelerating QUIC Migration for Ultra-Low-Latency Interactive Media

Research artifact for **SwiftShift**, a QUIC migration optimization framework for **ultra-low-latency (ULL) interactive media** (video conferencing, cloud gaming, XR/VR). It targets migration micro-stalls caused by **blocking path validation** and **timeout-amplified loss recovery** during access-network transitions.

## Paper

- **Venue**: NOSSDAV '26 (Hong Kong, Apr 4-8, 2026)
- **Authors**: Fangshuo Han, Dongbiao He, Xian Yu, Heng Pan, Xiaohui Nie, Yanbiao Li
- **DOI**: https://doi.org/10.1145/3798065.3798080

## Key Ideas

- **Adaptive migration triggering**: OS event-driven detection (e.g., Linux netlink) with filtering to reduce false positives and trigger within milliseconds.
- **NBV (Non-Blocking Validation)**: Overlaps path validation with strictly bounded speculative sending on a tentative path under anti-amplification constraints.
- **MAPR (Migration-Aware Proactive Retransmission)**: Proactively repairs likely-lost in-flight packets after a switch and resets loss-detection timers.

## Repository Layout

- xquic/tests/ `live_client.c`, `live_server.c`  \
  Minimal client/server programs for migration experiments.
- xquic/migration_test/ `run_live_server.sh`, `run_live_client.sh`  \
  Example end-to-end pipeline for live streaming tests.
- xquic/migration_test/analyse_decode_ts.py  \
  Optional post-processing and quality analysis.
- demo/  \
  Screen recording for stall tests.

## Build

1. Run `xquic_build.sh`.
2. Place a `test.mp4` under `xquic/migration_test/`.
3. Configure IP and interface for client/server (example):
   - iface: `enp6s20`
   - server: `192.168.68.125`
   - client: `192.168.68.126/127`

## Run (Quick Start)

- `xquic/migration_test/run_live_server.sh`
- `xquic/migration_test/run_live_client.sh`

## Key Implementation Files (src/)

- [xquic/src/transport/xqc_engine.c](xquic/src/transport/xqc_engine.c): migration trigger integration, NBV/MAPR execution path, and security bounds.
- [xquic/src/transport/xqc_frame.c](xquic/src/transport/xqc_frame.c): PATH_CHALLENGE/PATH_RESPONSE handling and validation flow.
- [xquic/src/transport/xqc_send_ctl.c](xquic/src/transport/xqc_send_ctl.c): anti-amplification checks and loss-detection timer control.
- [xquic/src/transport/xqc_multipath.c](xquic/src/transport/xqc_multipath.c): path state transitions and validation state tracking.

## Evaluation Outline

Recommended reporting metrics for migration performance:
- **Stall time per migration** (excess inter-frame gap)
- **Retransmitted packets per migration** (within a fixed post-switch window)
- **Receiver jitter-buffer slack** (e.g., 100 ms target)

Network dynamics can be emulated with `tc netem`, including a short blackout during the switch. For workload profiles, consider video call (30 FPS), cloud gaming (60 FPS), and XR/VR (90 FPS) with tight playout budgets.

## Citation

```bibtex
@inproceedings{han2026swiftshift,
  title={SwiftShift: Accelerating QUIC Migration for Ultra-Low-Latency Interactive Media},
  author={Han, Fangshuo and He, Dongbiao and Yu, Xian and Pan, Heng and Nie, Xiaohui and Li, Yanbiao},
  booktitle={Workshop on Network and Operating System Support for Digital Audio and Video (NOSSDAV '26)},
  year={2026},
  doi={10.1145/3798065.3798080}
}
```

## License

See `xquic/LICENSE` for licensing details.

# Changelog

## Unreleased

## 0.2.0 - 2026-09-25

- Automatic incident capture with selected critical latency/OOM aggregate triggers,
  fixed pre/post windows, consecutive incident grouping, and bounded private file rotation.
- Shared manual/automatic snapshot concurrency, visible publication failures, and
  offline trigger provenance without changing capture or protocol versions.
- Automatic capture is enabled by default. Existing v0.1 configs remain valid but
  now publish files under `/var/lib/blackbox/captures/auto`; set
  `auto_capture.enabled: false` to keep manual-only recording. Published files can
  use 1 GiB by default, with up to one additional file staged temporarily.
- Captures omit transient automatic writer state. Reports retain a critical verdict
  when verified trigger metadata outlives its source aggregates, while keeping
  captured-window observation counts separate.
- The v0.1 reader can parse format-1 automatic captures but ignores their trigger
  metadata; use the v0.2 analyzer when retained source aggregates are missing.
- Automatic encoding uses CPU, memory and disk I/O when triggered. A concurrent
  manual snapshot can return busy; pending incidents do not survive a restart.

## 0.1.0 - 2026-09-22

- Local Linux flight recorder with block I/O, scheduler, TCP and OOM sensors.
- Bounded in-kernel aggregation, selected event details and immutable history snapshots.
- Private atomic `.bbx` publication and offline JSON/terminal analysis.
- Best-effort sensor failure handling and opt-in strict startup/runtime policy.
- Explainable evidence gaps, scoped counters and retained latency highlights.
- Correct block flush bookkeeping and TCP reset endpoints/direction/provenance.
- Typed YAML configuration with strict validation and explicit CLI precedence.
- Small initial config surface with warn/critical thresholds and one control timeout.
- Collision-resistant capture filenames in the current directory when `-o` is omitted.
- Bounded zstd encoding windows that remain readable within fixed capture budgets.
- Internal bounded collection, transport, capture and report limits.
- Single-file Docker Compose setup, systemd configuration and generated CLI docs.
- Idempotent sensor shutdown and visible userspace overload warnings/counters.
- Explicit control-server overload errors, transient accept retry and meaningful
  healthcheck failure when no sensor remains active.
- Regression fixtures, capture fuzzing, Linux integration tests and contributor CI.
- Apache-2.0 project/userspace/docs licensing; BPF sources dual-licensed under
  Apache-2.0 OR GPL-2.0-only with GPL kernel ELF declarations.
- Contribution/security documentation and component license texts in runtime and release artifacts.

[Compatibility and upgrade policy](docs/compatibility.md)

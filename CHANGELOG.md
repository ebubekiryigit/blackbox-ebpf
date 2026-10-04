# Changelog

## Unreleased

- Discard stale scheduler wakeups when a task blocks, avoiding false long
  runnable-wait latencies. Decode OOM victim identity for both supported kernel
  tracepoint signatures, with PID-only evidence where the older signature lacks
  a task pointer.
- Treat the root cgroup as an unknown shared identity for correlation. Use the
  host cgroup namespace in Compose so process cgroup paths match the host.
- Share each sensor's detail quota across CPUs. Keep active-second quota state
  in a non-evicting map, reclaim old seconds during aggregate polling, and
  report quota-state failures separately from missing latency start records.
- Avoid repeating the full lookback in consecutive successful automatic
  captures while retaining trigger intervals that cross a file boundary. Include
  the first complete aggregate poll after the post-window deadline and retain
  the published boundary even when later file rotation fails.
- Move process metadata resolution to each sensor's existing reader goroutine so
  slow `/proc` reads cannot block aggregate polling or local control requests.
- Report limited or unknown socketless TCP sent-reset coverage from the kernel
  BTF signature in status, captures and analysis. Known capability limitations
  remain separate from collection-gap warnings; unknown capability stays a
  warning. Preserve packet peer tuples for resets sent by listening sockets.
  Retry nonstructural detail-budget
  cleanup failures without disabling valid aggregate sensors.
- On kernels whose retransmit tracepoint includes an error argument, exclude
  failed send attempts from TCP retransmit counts.
- Assess automatic trigger evidence per sensor family, so a critical signal in
  another subsystem cannot hide missing trigger evidence. Give removed
  `max_memory` settings a direct migration error.
- Under the fixed recorder budget, keep event details as long as `history` and
  memory permit, then fold the oldest segments into aggregate-only summaries.
  Status reports actual detailed and aggregate spans; captures and reports mark
  the portion whose individual details were compacted. Preserve complete rollups
  crossing a requested start, with requested and actual windows shown separately.
  Individual details keep the requested BOOTTIME boundary; delayed details in
  newer receipt-time segments remain selectable for their observation window.
- Run kernel integration in disposable x86_64 QEMU guests: 5.10, 6.1 and 6.12
  on PR/main, with 5.15, 6.6 and current stable added for manual/tag runs.
- Record the scheduler tracking-map capacity in new capture manifests.
- Raise recorder accounting from 32 to 64 MiB together with the decoded `.bbx`
  limit from 256 to 512 MiB. Larger captures require the accompanying analyzer;
  recording, snapshots and full JSON reports may use more memory. Encoded
  transport and archive entry limits are unchanged.
- Remove the misleading `max_memory` YAML/CLI setting. Recorder history keeps a
  fixed 64 MiB accounting budget; existing configs must remove `max_memory`
  before upgrade. This budget does not cap process RSS. The automatic storage
  byte quota accepts values above 1 TiB; file-count and scan safety bounds remain.
- Use BOOTTIME for kernel event timestamps and recorder windows while retaining
  MONOTONIC for block I/O and scheduler latency durations.
- Detect significant local realtime-to-boottime offset changes without stopping
  recording. Show the latest change in status, captures, and reports; use a
  current clock sample for UTC presentation without historical clock repair.
- Keep the pre-v1 `.bbx` format number at 1. Development captures without an
  explicit clock source are rejected; analyze them with the version that wrote
  them.

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

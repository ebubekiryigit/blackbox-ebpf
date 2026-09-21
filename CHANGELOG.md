# Changelog

`0.1.0-dev` is a development build label, not a published release. Public versioning
and compatibility policy will be defined before the first release; see
[compatibility](docs/compatibility.md).

## Unreleased

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
- Contribution/security documentation and component license texts in the runtime image.

# Compatibility and upgrades

Blackbox follows semantic versioning for application releases. v0.2 is a public
preview: patch releases preserve the v0.2 operator contracts, while a future minor
preview release may make an incompatible change when the benefit justifies it.
Every incompatible change must be explicit in the changelog and include an upgrade
path or a clear rejection error.

## Independent version contracts

| Contract | v0.2 value | Policy |
| --- | --- | --- |
| Application release | `0.2.x` | SemVer; latest patch is the supported preview |
| YAML configuration | Unversioned, with additive `auto_capture` settings | Patch releases preserve accepted v0.2 settings and meanings |
| `.bbx` capture | Format `1` | v0.2 readers read and write format 1; incompatible formats are rejected |
| Control socket | Protocol `1` | Client and daemon reject mismatched protocols; run matching releases |

The YAML schema intentionally has no `version` key. It is validated strictly, so
unknown settings fail instead of being silently ignored. A future incompatible
schema change will add a migration story only when a real migration exists.

`auto_capture.write_timeout` is additive. Configurations without it use 2 minutes,
independently of the control timeout. Earlier v0.2 builds used the control timeout
for automatic writes, which was 30 seconds by default. Set
`auto_capture.write_timeout: 30s` if preserving that deadline matters during an
upgrade; a longer write can also hold the snapshot writer lease longer.

Capture and socket discriminators are independent of the application version.
They prevent incompatible data from being misinterpreted and must not be bumped
for additive metadata. BPF object and kernel-map details remain internal build
contracts and are regenerated together.

## Capture behavior

The `.bbx` container is a checksummed zstd-compressed tar with a manifest, host
metadata, ordered JSON segments, and completion marker. Readers bound decoded
bytes, archive entries, zstd memory, and observation timestamps before accepting a
file. Large segment arrays are decoded one observation at a time, but the
decoded-byte limit is an archive-size limit, not an analyzer RSS cap. Parsed
objects, individual JSON values, zstd buffers, and other runtime state can
coexist in memory.

Unknown JSON fields are allowed for additive metadata. Missing optional fields use
their documented legacy interpretation. Synthetic fixtures under
`internal/capture/testdata/v1` are independent of the current writer and keep
format 1 behavior stable. Historical evidence is never rewritten to look more
complete.

There is no in-place capture migration command. If a future writer needs a new
format, migration must write a new destination and preserve the original. A reader
that does not support the format returns an actionable error instead of guessing.

## Upgrade from v0.1.0

There is no incompatible YAML, capture-format or socket-protocol change. The
default behavior does change: recording can now publish files without a manual
snapshot request.

v0.1 YAML files remain accepted, but automatic incident publication is enabled by
default when `auto_capture` is omitted. Before upgrading, review the writable
`/var/lib/blackbox/captures/auto` directory and rotation policy, or set
`auto_capture.enabled: false` to keep manual-only recording. Defaults allow up to
1000 published files or 1 GiB; staging one replacement can briefly require up to
another 512 MiB and maintains a 64 MiB filesystem free-space reserve. Manual
captures are not rotated. Automatic encoding uses CPU, memory, and disk I/O when
triggered, and a concurrent manual snapshot can return busy. Short retained
histories can produce partial automatic windows; the capture reports missing
coverage. Pending incidents do not survive daemon restart.

The v0.1.0 binary rejects the new `auto_capture` YAML keys and CLI flags, so
remove them before rolling back. Preserve the previous config and existing
captures. Its analyzer ignores automatic trigger metadata and may miss the
critical reason if the source aggregates were evicted. Analyze v0.2 automatic
captures with a v0.2 or newer reader.

Automatic trigger metadata and status fields are additive. Existing format-1
captures retain their interpretation. Older readers parse the file but ignore
the optional trigger metadata; current readers show it without adding it to
retained metric counts.
The capture format and socket protocol remain `1`; only the application version
changes to `0.2.0`.

## Upgrade an installation

1. Save any history you need. In-memory history is lost when recording stops.
2. Preserve the current config and captures.
3. Check the new binary with `blackbox version` and
   `blackbox config check --config PATH` before replacement.
4. Analyze representative old captures with the new binary.
5. Replace the binary or image and restart with the validated config.
6. Inspect `status`, sensor availability, and lifetime counters, then save and
   analyze a short new capture. In strict mode, verify every enabled sensor.

For systemd, replace `/usr/local/bin/blackbox` and restart the unit. For Compose,
keep `config.yml` and `captures/` outside the image and rebuild from the tagged
source checkout. Do not overwrite a customized config during an upgrade.

Release preparation updates `internal/version/VERSION` and `CHANGELOG.md`, runs
`make docs`, `make check`, and `make dist`, and runs privileged kernel integration
when sensor behavior changed. Local tests do not establish production support.

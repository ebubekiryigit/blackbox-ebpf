# Compatibility and upgrades

Blackbox v0.2 is a public preview. Application releases, YAML configuration,
`.bbx` captures, and the control socket have separate version contracts. Before
v1, development captures are not guaranteed to remain compatible across clock
semantics changes. Captures without a clock source are rejected rather than
silently interpreted as BOOTTIME. Preserve captures needed as evidence and
analyze them with the version that wrote them.

| Contract | Current development | Policy |
| --- | --- | --- |
| Application release | `0.2.0`; no new release version yet | Follow SemVer for releases |
| YAML configuration | Unversioned | Unknown keys fail; document any changed meaning |
| `.bbx` capture | Format `1`, BOOTTIME event and window timestamps | No migration path for older development captures |
| Control socket | Protocol `1` | Client and daemon reject mismatched protocols |

The YAML schema has no `version` key. `auto_capture.write_timeout` is additive
and defaults to 2 minutes independently of the control timeout. Earlier v0.2
builds used the control timeout for automatic writes, which was 30 seconds by
default. Set `auto_capture.write_timeout: 30s` if preserving that deadline
matters during an upgrade; a longer write can hold the snapshot writer lease
longer.
Consecutive automatic captures no longer repeat the full pre-trigger window
after a successful publication. Trigger detection and post-window timing are
unchanged; the selected windows may overlap by one aggregate interval to preserve
trigger evidence.

The next release removes the `max_memory` YAML key and `--max-memory` flag.
The name implied a total process memory cap, but it only controlled recorder
history accounting and could exceed the `.bbx` decoded archive budget. Remove
the key from existing config files before upgrading; strict parsing rejects it.
The recorder now uses a fixed 32 MiB accounting budget, so hosts previously
configured above that value may retain less history. Inspect `status` for the
oldest retained segment's age, evictions, and drops; analyze a capture for
sensor coverage. `auto_capture.max_storage` no longer
has a 1 TiB ceiling; the default stays 1 GiB and `max_files` still bounds the
per-write directory scan/sort work.
The control health response adds `retained_span_ns` without changing protocol
version `1`; older clients ignore it, and a newer client hides the age line
when talking to an older daemon that omits the field.

The `.bbx` container is a checksummed zstd-compressed tar with a manifest, host
metadata, ordered JSON segments, and a completion marker. Readers bound decoded
bytes, archive entries, zstd memory, and observation timestamps before accepting
a file. Large segments are decoded one observation at a time, but the decoded
byte limit is not an RSS cap. Independent archive fixtures test decoder behavior;
they are not a migration commitment for earlier development recordings.

Current kernel observations and recorder windows use BOOTTIME. A capture saves a
recent paired REALTIME/BOOTTIME anchor for UTC presentation plus the daemon's
latest detected offset discontinuity. It does not store separate recording
epochs or repair historical UTC timestamps. A realtime step does not reset
history. A one-hour Linux suspend advances BOOTTIME and excludes pre-suspend
events from `--last 10m`. A VM pause that also stops the guest BOOTTIME clock
cannot be inferred from guest timestamps alone.

## Upgrade from v0.2.0 to the next release

Restart the daemon to load the new BPF objects and BOOTTIME timestamp source;
save any in-memory history you need first. Preserve old `.bbx` files and the
binary that wrote them if their UTC interpretation matters. Remove
`max_memory` from YAML and startup flags before restarting; other
configuration and control socket contracts are unchanged. Verify new captures
with the new analyzer before retiring the previous binary.

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

Automatic trigger metadata and status fields are additive within v0.2. Older
readers may ignore trigger metadata; current readers show it without adding it
to retained metric counts.
The capture format and socket protocol remain `1`; only the application version
changes to `0.2.0`.

## Upgrade an installation

1. Save any history you need. In-memory history is lost when recording stops.
2. Preserve the current config and captures.
3. Check the new binary with `blackbox version` and
   `blackbox config check --config PATH` before replacement.
4. Analyze representative captures with the new binary. Use the previous binary
   for development captures without a clock source.
5. Replace the binary or image and restart with the validated config.
6. Inspect `status`, sensor availability, and lifetime counters, then save and
   analyze a short new capture. In strict mode, verify every enabled sensor.

For systemd, replace `/usr/local/bin/blackbox` and restart the unit. For Compose,
keep `config.yml` and `captures/` outside the image and rebuild from the tagged
source checkout. Do not overwrite a customized config during an upgrade.

Release preparation updates `internal/version/VERSION` and `CHANGELOG.md`, runs
`make docs`, `make check`, and `make dist`, and runs privileged kernel integration
when sensor behavior changed. Local tests do not establish production support.

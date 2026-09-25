# Compatibility and upgrades

Blackbox follows semantic versioning for application releases. v0.1 is a public
preview: patch releases preserve the v0.1 operator contracts, while a future minor
preview release may make an incompatible change when the benefit justifies it.
Every incompatible change must be explicit in the changelog and include an upgrade
path or a clear rejection error.

## Independent version contracts

| Contract | v0.1 value | Policy |
| --- | --- | --- |
| Application release | `0.1.x` | SemVer; latest patch is the supported preview |
| YAML configuration | Initial unversioned schema | Patch releases preserve accepted v0.1 settings and meanings |
| `.bbx` capture | Format `1` | v0.1 readers read and write format 1; incompatible formats are rejected |
| Control socket | Protocol `1` | Client and daemon reject mismatched protocols; run matching releases |

The YAML schema intentionally has no `version` key. It is validated strictly, so
unknown settings fail instead of being silently ignored. A future incompatible
schema change will add a migration story only when a real migration exists.

Capture and socket discriminators are independent of the application version.
They prevent incompatible data from being misinterpreted and must not be bumped
for additive metadata. BPF object and kernel-map details remain internal build
contracts and are regenerated together.

## Capture behavior

The `.bbx` container is a checksummed zstd-compressed tar with a manifest, host
metadata, ordered JSON segments, and completion marker. Readers bound decoded
bytes, archive entries, zstd memory, and observation timestamps before accepting a
file.

Unknown JSON fields are allowed for additive metadata. Missing optional fields use
their documented legacy interpretation. Synthetic fixtures under
`internal/capture/testdata/v1` are independent of the current writer and keep
format 1 behavior stable. Historical evidence is never rewritten to look more
complete.

There is no in-place capture migration command. If a future writer needs a new
format, migration must write a new destination and preserve the original. A reader
that does not support the format returns an actionable error instead of guessing.

## Unreleased automatic capture feature

Source builds enable automatic incident publication by default. Existing configs
inherit the new defaults. Short retained histories can produce partial automatic
windows; the capture reports the missing coverage. Review the writable output
directory and rotation policy before deploying a source build.
The v0.1.0 binary does not accept the new `auto_capture` YAML keys or CLI flags.
Preserve the previous config when rolling back.

Automatic trigger metadata and status fields are additive. Existing format-1
captures retain their interpretation. Older readers ignore the optional trigger
metadata, while current readers show it without adding it to retained metric counts.
Application, capture and socket version values have not changed in development.

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

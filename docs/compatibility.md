# Compatibility and upgrades

Blackbox has no published release or public migration history yet. `0.1.0-dev` is
only a build label. The current YAML shape is the initial pre-release format and has
no version field. It is validated strictly, so unknown settings fail instead of
being silently ignored.

Captures and the private socket include internal numeric discriminators so readers
and peers reject incompatible data instead of misinterpreting it. Those values are
implementation guardrails, not published product versions. Public compatibility
rules will be defined with the first release.

## Current capture behavior

The current `.bbx` container is a checksummed zstd-compressed tar with a manifest,
host metadata, ordered JSON segments, and completion marker. Readers bound decoded
bytes, archive entries, zstd memory, and observation timestamps before accepting a
file.

Unknown JSON fields are allowed for additive metadata. Missing optional fields use
legacy interpretation. New critical-latency counters and thresholds are optional
fields; older captures cannot infer a critical policy that was never recorded.

Synthetic regression fixtures under `internal/capture/testdata/v1` are independent
of the current writer. Earlier TCP direction and block-I/O unmatched semantics
remain as recorded. Historical evidence is never rewritten to look more complete.

There is no capture migration command. Before the first release, an incompatible
change may replace the pre-release format and fixtures. The first public release
must define whether future incompatible changes retain bounded readers or provide a
migration that writes a new destination without replacing the original.

## Upgrade an installation

1. Save any history you need. In-memory history is lost when recording stops.
2. Preserve the current config and captures.
3. Run the new binary's `version` and `config check --config PATH` before replacement.
4. Check representative old captures with the new offline analyzer.
5. Replace the binary or image and restart with the validated config.
6. Inspect `status`, sensor availability, and lifetime counters, then save and analyze
   a short new capture. In strict mode, verify every enabled sensor initialized.

For systemd, replace `/usr/local/bin/blackbox` and restart the unit. For Compose,
keep `config.yml` and `captures/` outside the image, then run
`docker compose up -d --build` from a source checkout. Use versioned images for a
release deployment.

Before the first release, define the public configuration compatibility policy.
For a release, update the application version once, update CHANGELOG, run
`make docs`, `make check`, `make generate` when sensor code changed, and execute
real-kernel integration. Local tests do not establish production support.

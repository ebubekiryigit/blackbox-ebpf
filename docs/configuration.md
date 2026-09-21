# Configuration

Blackbox exposes a small operator schema. Allocation sizes, parser limits, kernel
map capacities, report row counts, and archive safety limits are bounded internal
defaults in `internal/config/defaults.go`; they are not deployment tuning knobs.
[config.example.yml](../config.example.yml) and the [CLI reference](cli.md) are
generated from the typed schema with `make docs`.

## Load and validate

A file is optional for commands that create or validate a recording configuration:
`daemon`, `capture`, `config check`, and `config show`. When `--config` is present,
precedence is:

1. Compiled defaults.
2. The explicit YAML file.
3. Explicit CLI flags, including `--strict=false`.
4. Semantic validation.

Unprovided flags do not erase YAML values. Viper is isolated inside the loader and
the application receives only a typed `Config`. Blackbox does not discover a file,
read setting overrides from environment variables, interpolate values, or reload a
file while running.

```sh
cp config.example.yml config.yml
blackbox config check --config config.yml
blackbox config show --config config.yml
blackbox config show --config config.yml --history 3m --strict=false
```

The v0.1 configuration format has no top-level version key. YAML validation rejects
unknown and duplicate keys, multiple documents, malformed
types, anchors, aliases, merge keys, and null values. A malformed value cannot be
rescued by a CLI override.

Durations use Go syntax such as `250ms`, `30s`, `2m`, or `1h`. `max_memory` uses a
whole binary quantity such as `16MiB` or `1GiB`. Booleans must be `true` or `false`.
Sensors must be a YAML sequence containing one or more unique values from
`block_io`, `scheduler`, `tcp`, and `oom`.

## Operator settings

| Setting | Meaning |
| --- | --- |
| `log_level` | Daemon stderr verbosity: `debug`, `info`, `warn`, or `error` |
| `history` | Rolling daemon retention from 1 second to 24 hours |
| `max_memory` | Retained recorder-data budget from 1 MiB to 1 GiB |
| `sensors` | Enabled signal families |
| `strict` | Stop if any enabled sensor cannot initialize or fails permanently |
| `poll_interval` | Aggregate collection interval from 100 ms to 1 minute, no longer than history |
| `timeout` | End-to-end local control and snapshot deadline from 1 second to 10 minutes |
| `thresholds.*.warn` | Selects slow event details and produces a warning signal |
| `thresholds.*.critical` | Produces a critical signal; must exceed the corresponding warn threshold |

Warn and critical thresholds apply to device I/O request latency and scheduler
runnable wait, as named in the example. They do not measure application request
latency or CPU execution time and do not establish causality.

`history` applies to the daemon. The standalone `capture` command uses its explicit
`--duration` as both recording duration and retained window. `snapshot --last`
selects a shorter part of the daemon's history. If `--last` is omitted, the client
uses the daemon-advertised history. `status` and `snapshot` do not read a config
file because the running daemon is the source of truth. The Unix socket path is a
CLI-only endpoint choice rather than persisted recording configuration. Pass the
same `--socket` to `daemon`, `status`, and `snapshot` for a non-default endpoint,
and use `--timeout` when a client deadline must differ. The file's `timeout` bounds
server-side work. A control request ends at the earlier of the daemon deadline and
the client's `--timeout` deadline.

`max_memory` covers recorder backing capacity and retained strings. It excludes BPF
maps and rings, queues, process metadata, Go runtime, and compression workspace.
When any bounded stage overloads, lifetime counters expose dropped or suppressed
details. The daemon logs the first userspace overload and reports exact totals in
status and captures.

Settings are read at process startup. Validate changes before restarting. A daemon
restart loses unsaved history.

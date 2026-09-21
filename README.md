# Blackbox

**Keep the evidence from before a Linux incident.**

Blackbox is a local eBPF flight recorder. A small daemon keeps bounded rolling
history in memory. When something goes wrong, save the preceding window to a
private `.bbx` file and analyze it offline on Linux or macOS. Blackbox has no
external service, database, or listening TCP port.

| Signal | Captured evidence |
| --- | --- |
| Block I/O | Device request latency, histograms, and slow request details |
| Scheduler | Runnable-to-running latency and slow task details |
| TCP | Retransmissions and sent/received reset observations with endpoints |
| OOM | Kernel-selected out-of-memory victims |

Reports separate workload signals from missing evidence. Warn and critical latency
thresholds classify observations without claiming a root cause. Collection loss,
rate limiting, and unavailable sensors remain visible in status and captures.

> Blackbox is a development preview. Linux server compatibility and sustained-load
> measurements remain on the [roadmap](ROADMAP.md). There is no production overhead
> guarantee yet.

## Run with Docker

Docker Compose v2 is the shortest path from a source checkout:

```sh
make up
make status
```

`make up` creates `config.yml` from the documented example only when the file does
not exist, creates `captures/`, builds the `blackbox` image, and starts the daemon.
It never overwrites an existing config. Edit `config.yml` and run
`docker compose up -d` to apply changes. A restart discards unsaved history.

Save and analyze the daemon's configured history:

```sh
capture_path=$(docker compose exec -T blackbox /app/blackbox snapshot)
docker compose exec -T blackbox /app/blackbox analyze "$capture_path"
```

Compose runs commands in `/captures`, so an omitted `-o` creates a unique file in
the host `captures/` directory. Successful `capture`, `snapshot`, and `demo`
commands write only the absolute saved path to stdout, so scripts can capture it;
diagnostics and errors use stderr. Use `--last 30s` to request a shorter window.
Capture destinations are private and must not already exist. Offline analysis does
not need a privileged container:

```sh
docker run --rm blackbox version
docker run --rm -v "$PWD/captures:/captures:ro" blackbox analyze /captures/incident.bbx --verbose
```

Recording requires Linux, kernel BTF, and permission to load BPF programs. Compose
uses the Linux host PID and network namespaces and mounts `/sys/kernel/btf`
read-only. Docker Desktop records its Linux VM, not the macOS kernel. See
[host requirements](docs/operations.md#host-requirements-and-docker-mounts) before
a server deployment.

## Run a Linux binary or systemd

The target host needs no Go compiler, kernel headers, or libbpf shared library.
Embedded CO-RE bytecode is part of the static binary.

```sh
make build-linux
sudo install -m 0755 bin/blackbox-linux-amd64 /usr/local/bin/blackbox
sudo install -d -m 0755 /etc/blackbox
sudo install -m 0600 config.example.yml /etc/blackbox/config.yml
sudo blackbox config check --config /etc/blackbox/config.yml
sudo blackbox daemon --config /etc/blackbox/config.yml
```

Use `blackbox-linux-arm64` on ARM hosts. From another terminal:

```sh
sudo blackbox status
sudo blackbox snapshot
blackbox analyze ./blackbox-snapshot-20260921T113812Z-7f3a91.bbx
blackbox analyze ./blackbox-snapshot-20260921T113812Z-7f3a91.bbx --json
```

The config install command is for a fresh installation. Preserve and validate the
existing `/etc/blackbox/config.yml` during upgrades instead of overwriting it.

For managed startup, follow the [systemd instructions](docs/operations.md#systemd).

## Configure

The operator surface is intentionally small:

- log level, retained history, and retained-memory budget
- enabled sensors and best-effort or strict failure behavior
- aggregate polling interval and local control timeout
- block I/O and scheduler warn/critical latency thresholds

Configuration precedence is **compiled defaults → explicit YAML file → explicit CLI
flags → validation**. No file is discovered implicitly. Unknown or duplicate keys,
multiple YAML documents, invalid types, and unsafe values fail before recording.

```sh
blackbox config check --config config.yml
blackbox config show --config config.yml --history 2m
blackbox daemon --config config.yml --strict --sensors block_io,scheduler
blackbox capture --config config.yml --duration 30s
blackbox analyze incident.bbx --color=never > report.txt
```

Without `-o`, `capture` and `snapshot` write unique names such as
`blackbox-capture-20260921T113812Z-7f3a91.bbx` in the current directory and write
the absolute path to stdout. Snapshot names use the same format with a `snapshot`
prefix.
Use `-o` when automation requires a fixed destination.

`capture` has one window setting: `--duration`. Daemon retention uses `history` or
`--history`; snapshots use `--last`. The daemon's configured `timeout` bounds its
side of a control operation, including snapshot selection and transfer.
Standalone `capture` refuses to start a second recorder when a daemon is reachable
at the default control socket; use `snapshot` to save the daemon's existing history.

The daemon is the source of truth after startup. `status` and `snapshot` connect to
its control socket and do not reload its YAML file. The socket path is intentionally
CLI-only: pass the same `--socket` to `daemon`, `status`, and `snapshot` for an
uncommon non-default endpoint. Clients use the default endpoint and deadline unless
`--socket` or `--timeout` is explicitly supplied. A request ends at the earlier of
the daemon and client deadlines.

Best-effort is the default. Unavailable or permanently failed sensors are recorded
as missing coverage while remaining sensors continue. `--strict` requires every
enabled sensor to initialize and remain operational. Either mode fails if no sensor
is usable.

`max_memory` bounds retained recorder data, not total RSS. Kernel maps, bounded
queues, Go runtime, and snapshot work are additional. See the commented
[example config](config.example.yml), [configuration guide](docs/configuration.md),
[generated CLI reference](docs/cli.md), and [report guide](docs/operations.md#reading-a-report).

## Develop

```sh
make build
./bin/blackbox demo -o demo.bbx
./bin/blackbox analyze demo.bbx
make check
```

Ordinary builds use committed embedded bytecode. Sensor changes require
`make generate` and `make integration` on a BTF-enabled Linux kernel or Docker VM.
The developer-only BPF compiler image is defined in `Dockerfile.tools`; it is not
part of the runtime image. See [CONTRIBUTING.md](CONTRIBUTING.md).

[Architecture](docs/architecture.md) · [Operations](docs/operations.md) ·
[Compatibility and upgrades](docs/compatibility.md) · [Roadmap](ROADMAP.md) ·
[Security](SECURITY.md)

Go/userspace code and documentation are licensed under [Apache-2.0](LICENSE).
BPF sources are dual-licensed under `Apache-2.0 OR GPL-2.0-only`; their ELF programs
declare `GPL` to the Linux kernel for GPL-only helpers. See the
[component license guide](LICENSES/README.md).
Dependency license and notice files are tracked under [third_party](third_party/README.md)
and included in the runtime image.

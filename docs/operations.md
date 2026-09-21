# Operations

## Host requirements and Docker mounts

Recording targets Linux 5.8+ with `/sys/kernel/btf/vmlinux`, the required hooks and
permission to load BPF programs. Hook or policy restrictions can make a sensor
unavailable even on a newer kernel. Root and a privileged container are the current
supported privilege model; narrower capability configurations are not validated.
A built binary needs no runtime compiler or kernel headers.

Compose runs with host PID and network namespaces:

| Path / setting | Use |
| --- | --- |
| `/sys/kernel/btf` read-only | Kernel type information for CO-RE relocation and tracepoint layout |
| `/etc/blackbox/config.yml` read-only bind | Explicit operator configuration |
| `/captures` writable bind | Explicitly requested snapshots |
| `pid: host` | Host process metadata from `/proc` |
| `network_mode: host` | Host namespace for operation and local workload testing |

The current sensors do **not require** an additional `/sys/fs/bpf` mount: program
and map lifetime is managed through file descriptors, with no object pinning.
They also do not require `/sys/kernel/debug` or tracefs mounts: raw tracepoint
attachment uses a BPF syscall rather than tracefs discovery. A separate host
`/proc` bind is unnecessary with the host PID namespace. Revisit mount requirements
if attachment methods, pinning or namespace isolation change.

The private control socket stays inside the container. Use `docker compose exec`
for status and snapshots. No socket volume or host socket access is required.

Docker Desktop observes the Linux VM kernel and its processes. A normal Linux
server deployment observes the server kernel. Neither configuration requires an
external service or listening TCP port.

The runtime image entrypoint is `/app/blackbox`, its image working directory is
`/app`, and it has no default command. Compose supplies `daemon` explicitly and
uses `/captures` as the working directory so generated snapshots reach the bind
mount.

## Recording and failure policy

```sh
sudo blackbox daemon --config /etc/blackbox/config.yml
sudo blackbox status
sudo blackbox snapshot
```

Snapshots request preceding history. Use standalone `capture --duration 30s` when
no daemon is running; it refuses to start a second recorder when the default daemon
socket is active. Restarting
loses unsaved history. Captures have `0600` permissions and never overwrite.
Without `-o`, snapshot and capture generate sortable unique names in the current
directory and write only their absolute paths to stdout. Explicit destinations are
still never overwritten. The daemon owns recording configuration after startup. Status and
snapshot clients use the control socket and do not reload the daemon's YAML. Use
`--socket` and `--timeout` directly for non-default client settings.
The socket path is CLI-only and is not accepted in YAML.

Default best-effort mode continues with remaining sensors when a subsystem cannot
initialize or fails permanently. Status, saved health and analysis expose the
missing coverage and its reason. With no usable sensors, startup fails.

```sh
sudo blackbox daemon --strict
sudo blackbox daemon --strict --sensors block_io,scheduler
```

Strict mode requires each enabled sensor to initialize and remain operational.
Failure returns a non-zero exit code. Sensors explicitly disabled by configuration
are not required. A strict failure does not automatically save a snapshot.

`status` returns a non-zero exit code when no sensor remains active, after rendering
the available diagnostics. The Compose healthcheck therefore marks a running but
non-recording daemon unhealthy. Partial best-effort coverage remains healthy while
at least one enabled sensor is recording.

## Systemd

On a Linux host, install the matching binary and a validated configuration:

```sh
sudo install -d -m 0755 /etc/blackbox
# Fresh install only: preserve existing customized config on upgrade.
sudo install -m 0600 config.example.yml /etc/blackbox/config.yml
sudo blackbox config check --config /etc/blackbox/config.yml
sudo install -m 0644 deploy/blackbox.service /etc/systemd/system/blackbox.service
sudo systemctl daemon-reload
sudo systemctl enable --now blackbox
sudo journalctl -u blackbox
```

The unit expects `/usr/local/bin/blackbox` and `/etc/blackbox/config.yml`. systemd
owns the private runtime directory and restarts on failure. Edit and validate config
before `systemctl restart blackbox`; unsaved history is lost. See [upgrades](compatibility.md).

## Resources

Normal observations remain in per-CPU histograms and counters, polled at the public
`poll_interval`. Details cover slow block I/O, scheduler waits, TCP
retransmissions/resets, and OOM victims. Internal detail quotas are bounded and
partitioned across possible CPUs; OOM is exempt. Aggregate counters still include
observations whose details were suppressed.

`max_memory` bounds retained recorder data, including backing buffer
capacity. It is **not an RSS limit**. BPF maps/rings, ingress, metadata cache, Go
runtime and snapshot compression add memory. One in-flight snapshot may keep
otherwise evicted segments alive until writing finishes. Status exposes BPF memory
estimates when the kernel supplies them. High load may shorten retained history
or drop details; inspect counters alongside the report.

All operator settings and CLI parameters are in the generated [CLI reference](cli.md)
and [example config](../config.example.yml). See [configuration](configuration.md)
for fixed internal budgets, public settings, and precedence. An unset `snapshot --last` requests the
daemon's configured history. An explicit `--last` cannot exceed that history;
shorter retained coverage is reported.

## Reading a report

```sh
blackbox analyze incident.bbx
blackbox analyze incident.bbx --json
```

The terminal report starts with a verdict and a short per-subsystem assessment.
Workload observations and evidence quality are shown separately:

| Verdict | Meaning |
| --- | --- |
| Green: **No anomalies observed** | No recorded latency threshold exceedances, TCP retransmits/resets or OOM victims in measured evidence |
| Amber: **Signals to review** | Slow latency or TCP events were observed; resets can be expected and are not themselves proof of a fault |
| Red: **Critical latency observed** | I/O or scheduler latency crossed its captured critical threshold; this classifies severity without identifying a root cause |
| Red: **OOM victims observed** | The kernel selected processes as out-of-memory victims |
| Amber: **Evidence limited / insufficient** | Missing sensors, metric intervals or observations limit the conclusion |
| Cyan: **No activity to assess** | Monitoring yielded no measured activity; I/O/scheduler latency cannot be assessed |

A green workload result never certifies the entire system as healthy. If I/O
starts are missing, the report can show no anomalies in measured requests while
also highlighting incomplete I/O evidence. Explicitly disabled sensors are
excluded from the assessment. Zero observations are described by subsystem.

Colors are automatic on a terminal. Redirected output is plain; `NO_COLOR` (when
nonempty) or `TERM=dumb` disables automatic color. An explicit flag overrides
automatic selection. Symbols and explanatory labels remain in plain output.

```sh
blackbox analyze incident.bbx --color=always
blackbox analyze incident.bbx --color=never > report.txt
blackbox analyze incident.bbx --verbose
blackbox status --verbose
```

`--verbose` adds lifetime diagnostics and expands the bounded text presentation.
Normal output omits empty tables. `--json` retains all evidence and never
contains presentation colors, regardless of `--color`.
Wide tables become labeled rows when endpoints or terminal width would cause
columns to overflow. The largest retained latency is highlighted even when its
event falls beyond the displayed timeline limit.

Latency p50/p95/p99 values are logarithmic histogram bucket bounds, not exact
quantiles. Counts and histograms include complete aggregate intervals only;
partial boundary intervals are excluded rather than estimated.
The latency cards show measured and untimed completions together. Percentiles
cover measured observations only; a low p99 can coexist with a severe individual
outlier, which is shown separately when its detail was retained.

TCP resets are **kernel observations**, not a count of unique connections or wire
packets. A loopback reset may appear once as sent and once as received. These
tracepoints do not establish successful delivery or capture every possible reset
path. A reset can be expected, for example after connecting to a closed port or
closing an established connection with `SO_LINGER=0`.
New details distinguish sent/received direction and preserve peer addresses even
when the sending hook has no socket. Only IP addresses and TCP ports are read
from packet headers; payloads are not collected. `--verbose` identifies this source.
Process/PID ownership is not collected for TCP; a missing owner does not mean the
process no longer exists. Kernel interrupt context is not a reliable socket owner.

Legacy reset details did not distinguish direction; the report shows their saved
endpoint pair with `↔`. Missing addresses are shown as **Endpoints unavailable**
and limit the evidence even when loss counters are zero. They cannot be recovered
from an existing capture; record a new window with the updated sensor.

Collection notes explain the consequence of each nonzero counter:

| Counter | Meaning and effect |
| --- | --- |
| **Unmatched / start missing** | A completion had no matching tracked dispatch/start. Its latency could not be calculated and is excluded from the histogram. This does not establish why the start was missing or prove a workload fault. |
| **Tracking failures / start unsaved** | Tracking state could not be retained. Some latency measurements may be missing. |
| **Ring reserve failures / buffer rejected** | The kernel detail buffer could not accept an event. Aggregate counts remain available; individual detail is missing. |
| **Detail suppressed / rate limited** | The bounded detail quota intentionally omitted events. Counts and histograms still include them. |
| **Detail decode failures / detail invalid** | Userspace rejected a malformed or unknown detail record. Aggregate counts and histograms remain available; individual detail is missing. |

Current-window collection notes sum sensor deltas in complete captured metric
intervals. Lifetime totals cover the entire daemon run; they are not additional
window losses. Historical-only sensor counters appear in verbose diagnostics and
do not turn an otherwise clear current window into a workload warning. Ingress
and recorder drops are lifetime-only: the report explicitly states that their
occurrence in this window is unknown. Memory evictions, unresolved metadata and
snapshot write failures are also lifetime diagnostics.

JSON preserves exact nanosecond timestamps, process start identities and evidence
references. The `assessment` object is the same verdict shown in the terminal:
`code`, `severity`, `signal_state` and `evidence_state` describe the result;
`coverage_reasons` identify sensor, scope, counter, count and evidence references.
`lifetime_diagnostics` remain separate from current-window gaps.
`latency_highlights` reference exact retained events, not histogram estimates.
`status` describes recorder health and collection notes; analyze a
snapshot to assess workload signals.

Block I/O measures device dispatch to final data completion; dispatched cache
flushes are timed independently. This does not measure the application's entire
`fsync` duration. Linux flush sequencing can complete the original WRITE again
after its data was consumed, or finish a data-less logical WRITE without its own
device dispatch. These zero-byte WRITE notifications are counted separately as
`bookkeeping_completions`, outside I/O counts/histograms and loss counters. They
appear in JSON and verbose diagnostics and do not degrade coverage. Actual
zero-byte device FLUSH operations remain latency measurements.

Old captures cannot distinguish those notifications from genuinely missing
starts, so their recorded `unmatched` warnings are preserved. Start a recorder
with the updated binary to collect the corrected counters. No capture format
version change is required for these optional JSON fields.

Requested-history warnings quantify the missing duration. New captures also
record when recording began, allowing a request that predates startup to be
explained directly; older captures do not infer that reason from lifetime counters.

Block I/O records issue context, which may be a kernel worker.
TCP ownership is unavailable. OOM identifies the victim.
Coincident signals describe timing, not causation.

No packet payloads, application queries, argv or process environments are
collected. Captures do contain hostnames, process names, cgroup paths and endpoints;
handle that infrastructure metadata appropriately when sharing captures.

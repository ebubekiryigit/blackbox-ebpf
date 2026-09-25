# Architecture

Blackbox runs locally as a foreground daemon. It keeps recent kernel observations
in memory and exposes a private Unix socket for health and retroactive snapshots.
Analysis consumes only the saved file. There is no network listener or external
service dependency.

## Data flow and ownership

```text
C eBPF sensors → per-CPU aggregates + bounded detail rings
                         ↓
Go sensor readers → bounded ingress → application event loop
                                         ↓
                           rolling immutable segments
                                         ↓
Unix socket snapshot → streamed .bbx file → offline analyzer
```

| Layer | Responsibility |
| --- | --- |
| `bpf/` | Raw tracepoint programs, CO-RE field access, aggregation and detail quotas |
| `internal/sensor` | Embedded object loading, attachment, ring decoding, aggregate polling and health |
| `internal/autocapture` | Deterministic incident state, bounded trigger metadata, private rotating publication |
| `internal/app` | One state-owning event loop, monotonic clock, process enrichment and failure policy |
| `internal/recorder` | Time/memory retention, sealed segments and immutable snapshot selection |
| `internal/control` | Private versioned Unix socket requests and capture streaming |
| `internal/capture` | Versioned container, integrity validation and atomic file publication |
| `internal/model` | Durable schema and shared counter meanings |
| `internal/analyzer` | Deterministic summaries, timeline, evidence and shared JSON/terminal assessment |
| `internal/config` | Loader-local Viper orchestration, strict YAML schema, typed settings and bounds |
| `internal/cli` | Commands, flags, color selection and recorder status |
| `internal/terminal` | Shared human formatting, color theme and terminal detection |

The recorder has one writer. Sealed segment contents never change, so snapshots
can share them while the writer continues. Active and boundary segments are
copied. Segment timestamp bounds avoid scanning every retained event on snapshot;
partial aggregate intervals are excluded rather than interpolated.

## Sensors and coverage

Sensors attach independently using raw tracepoints. Normal activity updates
per-CPU histograms and counters; only selected anomalies emit details. Userspace
polls aggregate deltas at the configured interval. The ring reader and per-CPU result buffers
are reused. A malformed or unknown detail record increments a userspace decode-loss
counter without stopping aggregate collection. Kernel maps, rings, ingress and recorder retention are bounded.
Zero-byte logical WRITE completion notifications from flush bookkeeping are
separate from device I/O measurements and missing-start counters. Actual cache
flush dispatches remain timed; no additional tracking map is needed.

Best-effort is default. An enabled sensor that cannot initialize is unavailable;
a permanently failed sensor is closed and marked error. Other sensors continue.
Previous observations and the missing coverage reason remain in the capture.
No working sensors means failure. With `--strict`, an enabled sensor's
initialization or permanent runtime failure terminates recording with an error.
Disabled sensors are outside the strict requirement.

Process identity includes TGID and start time to avoid merging reused PIDs.
Block I/O identifies dispatch context, TCP process ownership is not collected, and OOM details
identify the victim. Timing correlations are observations, not causal conclusions.
TCP reset details distinguish sent and received observations. Socket-less responses
read only addresses and ports from the incoming packet headers and reverse the
tuple; active resets use the socket's wire port even after its bind port is cleared.
Received reset tuples follow the incoming direction. Optional event metadata records
endpoint provenance and whether a socket was associated, without additional maps
or connection tracking. IRQ/current-task identity does not establish socket ownership.

## Automatic incidents

The recorder loop feeds aggregate deltas to a trigger controller. One fixed window
groups overlapping triggers; the next trigger opens another window immediately.
At most one additional waiting window merges triggers while file output is busy.
Snapshot selection stays on the single writer; a background worker publishes it.
Manual and automatic snapshots share one writer lease. The private output directory
rotates only automatic files within count and byte limits. Optional trigger metadata
in the capture manifest lets offline analysis explain why the file was created.

## Persistence and compatibility

The current `.bbx` container is a checksummed zstd-compressed tar with manifest,
host metadata, sequential JSON segments and a completion marker. The reader
validates entry types, names, ordering, size, completion and observation timestamps.
Publication validates a temporary private file before atomically creating the
requested path; existing files are never overwritten. Capture decoding, zstd
memory, and entry counts have fixed bounded safety limits.

Application version, capture format version, config schema and socket protocol are
separate contracts. Product releases use `internal/version/VERSION`; schema and
protocol changes must consider existing captures and clients. The durable model
and offline analyzer do not depend on sensors or control sockets.

See [configuration](configuration.md) and [compatibility](compatibility.md) for the
merge boundary, independent contracts and upgrade procedure.

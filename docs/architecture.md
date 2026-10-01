# Architecture

Blackbox runs locally as a foreground daemon. It keeps recent kernel observations
in memory and exposes a private Unix socket for health and retroactive snapshots.
Analysis consumes only the saved file. There is no network listener or external
service dependency.

## Data flow and ownership

```text
C eBPF sensors → per-CPU aggregates + bounded detail rings
                         ↓
Go sensor readers + process metadata → bounded ingress → application event loop
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
| `internal/app` | One state-owning event loop, clock sampling, sensor-reader metadata wiring and failure policy |
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
copied. Under its fixed accounting budget, the recorder folds the oldest
detailed segments into one-minute aggregate-only segments before dropping
aggregate history. There is no fixed detailed-history duration: it depends on
the configured `history` and actual load. The active rollup is copied for a
snapshot; sealed rollups are immutable. Segment timestamp bounds avoid scanning
every retained event on snapshot; partial aggregate intervals are excluded
rather than interpolated.

## Timekeeping

Kernel event timestamps and recorder windows use `CLOCK_BOOTTIME`. Block I/O and
scheduler latency durations use `CLOCK_MONOTONIC`, so Linux suspend time does
not inflate those performance measurements. The daemon samples
`CLOCK_REALTIME` with `CLOCK_BOOTTIME` on its existing poll and query paths.
Current UTC in status comes from a fresh realtime sample, never from an
extrapolated startup timestamp.

A significant change in `CLOCK_REALTIME - CLOCK_BOOTTIME` is logged and
exposed as the latest daemon-lifetime clock discontinuity in status, captures,
and reports. Recording and history continue unchanged. Each capture uses a
current paired realtime/boottime sample to present its event times in UTC.
This is a projection, not historical clock repair: event UTC times before a
clock step can be shifted. `--last` and retention use BOOTTIME directly, so a
one-hour Linux suspend excludes pre-suspend events from a ten-minute window.
A virtual-machine pause that stops the guest's BOOTTIME clock is different:
that elapsed host time cannot be inferred from the guest clock alone.

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
Each sensor reader resolves process metadata before handing a detail to the bounded
ingress queue. Slow `/proc` reads do not block aggregate polling or the recorder
loop; resolution failures are counted in daemon health.
Block I/O identifies dispatch context, TCP process ownership is not collected, and OOM details
identify the victim when the kernel exposes its task. On kernels exposing only a victim PID,
the detail marks process identity as unavailable. Timing correlations are observations, not causal conclusions.
TCP reset details distinguish sent and received observations. Socketless sent
resets require a tracepoint signature exposing the incoming packet. Blackbox
checks its BTF signature and marks coverage limited on older signatures, or
unknown when the capability cannot be established. This limitation is saved in
capture health and considered during offline analysis. When available, the
socketless response reads addresses and ports from packet headers and reverses
the tuple; active resets use the socket's wire port even after its bind port is cleared.
Received reset tuples follow the incoming direction. Optional event metadata records
endpoint provenance and whether a socket was associated, without additional maps
or connection tracking. IRQ/current-task identity does not establish socket ownership.
For kernels whose TCP retransmit tracepoint includes an error argument, the
sensor counts only calls with a successful transmission result. Older kernel
signatures retain their original success-only tracepoint behavior.

## Automatic incidents

The recorder loop feeds aggregate deltas to a trigger controller. One fixed window
groups overlapping triggers; the next trigger opens another window immediately.
Successful consecutive files avoid repeating the full lookback while retaining
an aggregate interval that crosses their boundary.
Selection waits for the first complete aggregate poll after the configured
post-trigger deadline and uses that poll boundary as the saved file end.
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

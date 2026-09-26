# Development

Use the Go version in `go.mod`. Ordinary builds use committed embedded sensor objects.
`Dockerfile.tools` has Clang/LLVM and libbpf headers for regeneration. The main
Dockerfile has only build and scratch runtime stages; runtime contains the binary
and license texts and needs no compiler.
Generation/integration reuse named Docker module/build caches; override
`GO_MOD_VOLUME` and `GO_BUILD_VOLUME` in Make when separate caches are needed.

## Adding a feature

Identify the owning layer in [architecture](architecture.md). Keep collection,
orchestration, retention, persistence and analysis separate. Discuss significant
product/design choices, new runtime dependencies, changed privileges and collection
boundaries with the maintainer. Avoid speculative future layers.

Define bounded buffers, unavailable coverage and loss semantics alongside new
observations. Test best-effort and strict behavior when changing sensor failures.
Human output separates anomalies from evidence gaps, explains nonzero counters and
works without color. JSON is complete and independent of presentation options.

Operational defaults and bounds belong in `internal/config/defaults.go`. Extend the
typed schema, validation and loader tests together; Viper remains loader-local.
Kernel map capacities are supplied by the Go loader before creation. The histogram
ABI header is generated from durable model constants; changing that layout is a
capture compatibility decision. Test wire structure sizes against embedded objects.

## Tests

```sh
make check          # unit/regression tests, vet, Linux builds, docs and licenses
make generate       # histogram ABI + embedded Go/ELF files after C changes
make integration    # privileged real-kernel tests in Linux / Docker Desktop VM
make bench          # recorder recording, polling and snapshot allocation benchmarks
make fuzz           # bounded untrusted capture decoder fuzz run
make licenses       # regenerate dependency licenses/notices after Go dependency changes
make dist           # build versioned Linux release archives and checksums
```

Portable tests cover config precedence/strictness, retention/time boundaries,
immutable snapshots, memory pressure, archive integrity/publication, legacy fixtures,
coverage assessment, output limits/colors and control framing/cancellation. Automatic capture tests cover fixed windows,
coalescing, back-to-back incidents, writer contention, storage rotation, and failure recovery. CLI
regressions exercise a fresh synthetic capture through offline analysis and config
inspection. They require no BPF privileges; socket tests need local Unix sockets.

Kernel tests load every enabled sensor, exercise fsync flush bookkeeping and genuine
tracking-map exhaustion, scheduler activity and IPv4/IPv6 reset tuples, and verify
OOM attachment without inducing a host OOM. A daemon → socket → snapshot → analyzer
scenario uses non-default resource settings. Automatic capture integration generates
bounded disk/scheduler activity and reads a real automatically published capture. Tests use their own BPF objects, files
and ports; their loopback events may be visible to an existing host-wide recorder.
Do not restart existing recordings or disturb remote workloads for tests.

Commit `*_bpfel.go`, `*_bpfel.o` and `bpf/abi.h` together. Regenerate using the
developer tools image to avoid compiler-version drift. CI checks regeneration
and performs portable checks on Linux/macOS. Kernel CI runs for pull requests and
pushes to `main` on an ephemeral privileged runner; local checks do not replace
the server compatibility/load matrix.

Recorder benchmarks do not measure full daemon RSS, kernel hook overhead or
production CPU. Compare repeated runs on the same hardware. Report workload,
CPU/RSS, map memory, snapshot latency, retained coverage and drops together before
making overhead claims.

### Capture decoder baseline (2026-09-26)

`BenchmarkCaptureDecode` in `internal/capture/capture_bench_test.go` decodes one
independently generated format-1 archive with 200,000 OOM events in one segment.
Each event has a distinct six-digit process name. The segment is 11,800,061
decoded JSON bytes (11.25 MiB); the zstd archive was approximately 0.1007 MiB.
The benchmark uses default capture limits and reads the archive from memory.
Archive construction precedes `b.ResetTimer`, so `ns/op` and `B/op` measure the
decode loop, not fixture generation.

The pre-streaming reader came from commit
`072a4356f23b9b70aede83c37c2c00964ab63af1`. The streaming reader was tested
at `de5602db2f0495441d1eb4afb91b5f80ddb32b13`; its decoder code is unchanged
from its introduction in `a9f330a6ae47291d2fd76a358cd2388c8a6380d4`. The same
benchmark source was copied into an isolated checkout of the older commit.
Measurements used Go 1.27.1 on macOS 26.5.1, Darwin 25.5.0/arm64, with the CPU
reported by Go as Apple M4 and `GOMAXPROCS=1`.

| Reader | Median decode time | Allocated per decode | Allocations per decode | Peak RSS, median (range) |
| --- | ---: | ---: | ---: | ---: |
| Pre-streaming | 88.0 ms | 300,933,728 B | 200,962 | 227 MB (226–235 MB) |
| Streaming | 125.7 ms | 320,972,354 B | 400,991 | 178 MB (153–207 MB) |

Time and allocation figures are medians of five `-benchtime=3x` benchmark runs:

```sh
GOMAXPROCS=1 go test ./internal/capture -run '^$' -bench '^BenchmarkCaptureDecode$' -benchmem -benchtime=3x -count=5
```

Peak RSS came from four separate one-iteration test processes per reader, using
macOS `/usr/bin/time -l` and its `maximum resident set size` field. Build the
test binary first, then run it from `internal/capture` so it finds the fixture:

```sh
GOMAXPROCS=1 go test -c -o /tmp/blackbox-capture.test ./internal/capture
(cd internal/capture && GOMAXPROCS=1 /usr/bin/time -l /tmp/blackbox-capture.test -test.run '^$' -test.bench '^BenchmarkCaptureDecode$' -test.benchtime=1x -test.count=1)
```

RSS includes the Go runtime, benchmark harness and fixture construction; it is
not a decoder-only peak or a hard memory bound. On this workload streaming used
less peak process memory but more CPU and total allocations. Keep streaming for
v0.2; revisit with pprof and Linux measurements if production capture sizes
make the allocation cost material.

## Documentation and versions

```sh
make docs           # generate config.example.yml, docs/cli.md and Docker Go default
make docs-check     # fail if generated copies are stale
```

Edit source rather than generated artifacts. Keep CLI help, example config, README,
Make targets, Docker/Compose and systemd commands consistent. Test changed first-use
commands. Change only `internal/version/VERSION` for application bumps; storage,
config and socket versions have separate contracts described in
[compatibility](compatibility.md).

Tracked docs are concise English references: README for first use, architecture for
ownership, operations/configuration for deployment, this guide and CONTRIBUTING for
changes. Include implemented behavior and limitations; remove stale commands.
Private investigations and decision drafts belong under ignored `.local/`.

## Releases

Application releases use the single version in `internal/version/VERSION`. Move
completed entries from `Unreleased` into a dated `CHANGELOG.md` section. Prepare
the GitHub release description from that section when publishing. Run the full
validation, then build artifacts:

1. Compare the previous release tag with the candidate for defaults, accepted
   YAML/CLI settings, emitted files, privileges, CPU/memory/disk use, capture
   interpretation, socket behavior and rollback. Identify both incompatible
   changes and compatible changes that alter operations. Record the impact and
   migration steps in `CHANGELOG.md` and [compatibility](compatibility.md); align
   README, SECURITY and deployment docs. Carry these notes into the GitHub release
   description when publishing.
2. Test old capture fixtures with the new reader. If new optional metadata can
   change a report's meaning, check how the previous reader presents a new
   capture and document any downgrade risk. Validate an existing config and the
   new example, plus a manual-only opt-out when a new default writes data.
3. Run the checks below and privileged kernel integration for recording changes.
   Inspect the archive contents, embedded binary versions, checksums and licenses
   for both architectures. Publish only after the release commit and tag are tested.

```sh
make docs
make check
make integration
make dist
```

`make dist` creates static Linux `amd64` and `arm64` tarballs plus SHA-256
checksums. Every archive includes the example config, systemd unit, project
licenses, and the reviewed runtime dependency notices. GitHub release automation
is intentionally not encoded yet; publish artifacts and a release description
drawn from the changelog only from the tested release commit and tag.

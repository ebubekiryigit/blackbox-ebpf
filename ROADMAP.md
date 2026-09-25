# Roadmap

Blackbox v0.2 is a public preview. Priorities focus on dependable local evidence,
bounded overhead and reproducible validation. Items are not release-date promises.

## Before a stable release

- [ ] Run a Linux server matrix: amd64/arm64, older and current BTF-enabled kernels,
  supported page sizes, cgroup layouts and restricted BPF policies. Record sensor
  availability and both best-effort/strict failure behavior.
- [ ] Measure full daemon and kernel overhead under controlled low/high event rates,
  long-running retention and concurrent snapshots. Publish hardware, workload,
  CPU/RSS, map memory, snapshot latency, drops and retained coverage together.
- [ ] Exercise sustained detail pressure, tracking-map exhaustion, slow/disconnected
  clients and memory eviction. Verify that incomplete evidence stays visible.
- [ ] Validate native systemd install, clean-host README steps and binary/container
  upgrades using preserved config and historical synthetic captures.
- [ ] Define the stable support matrix, overhead envelope and upgrade guarantees
  from the validation results above.

## Follow-up work to discuss

- Better TCP process attribution if a bounded design can identify ownership reliably
  without attributing interrupt context to the wrong process.
- Additional incident signals only with a specific operator use case, explicit
  resource budget, coverage semantics and a reproducible kernel test.
- Capture schema migrations when an actual incompatible schema exists, backed by
  immutable legacy fixtures and explicit reader compatibility.

The project currently has no runtime server, database, Kubernetes dependency or
remote analysis requirement. Product-scope and collection-boundary changes need
maintainer discussion.

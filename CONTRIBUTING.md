# Contributing to Blackbox

Start with [README.md](README.md), the [architecture](docs/architecture.md) and
[development guide](docs/development.md). Blackbox keeps recent kernel evidence
locally and analyzes saved captures offline. Preserve that scope and keep changes
small enough to review.

## Before writing code

For a bug, include a minimal reproduction, application version, Linux kernel,
architecture, deployment mode and relevant coverage counters. Remove infrastructure
metadata from public reports; do not attach production captures by default.
Report security vulnerabilities privately using [SECURITY.md](SECURITY.md).

Discuss significant features, runtime dependencies, privileges, data collection
boundaries and incompatible formats with the maintainer before implementing them.
Routine fixes and tests can go directly to a pull request.

## Implement and verify

1. Identify the owning layer; do not move kernel or socket access into offline analysis.
2. For a bug, add a failing behavioral regression first when practical. Check normal
   behavior, failure semantics and bounded allocations. Explain unavailable evidence.
3. Run `make check`. For C changes, run `make generate` and `make integration` on
   Linux or the Docker VM; commit generated Go/ELF files and `bpf/abi.h` together.
4. Update affected documentation. After changing commands, defaults or the Go
   version, run `make docs`; generated files are checked by `make docs-check`.
   After changing Go dependencies, run `make licenses` and review the generated
   third-party license and notice bundle.
5. Describe the concrete problem, resulting behavior, validation and compatibility
   impact in the pull request. Keep unrelated formatting and refactors separate.

`make bench` measures recorder operations. `make fuzz` exercises the untrusted
capture reader for a bounded local run. Real CPU/RSS and kernel overhead measurements
need representative workloads and hardware; a benchmark is not a deployment guarantee.
Do not restart someone else's recorder or perturb production workloads for tests.

## Defaults, configuration and upgrades

Operational defaults and bounds belong in `internal/config/defaults.go`; settings
flow through one validated typed `Config`. Viper belongs only in the config loader.
Changes must preserve strict YAML parsing and defaults → file → explicit flags.
Kernel schemas, histogram layout and tar framing are compatibility invariants,
not operator settings. Explain and test format/protocol changes before bumping them.
See [compatibility and upgrades](docs/compatibility.md).

Use English for tracked operator/developer docs. Document implemented behavior,
runnable commands and limitations; keep private investigations under `.local/`.
Maintain agreement among CLI help, generated examples, Make, Docker, systemd and README.

Go/userspace and documentation contributions use [Apache-2.0](LICENSE).
Contributions to BPF sources use `Apache-2.0 OR GPL-2.0-only`; preserve their SPDX
headers and the separate `GPL` ELF declaration. Preserve third-party copyright
and license notices unchanged. See the [component license guide](LICENSES/README.md).

Be respectful in issues and reviews, focus on the code and evidence, and avoid
personal attacks or publishing private information.

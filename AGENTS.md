# Working on Blackbox

Blackbox is a local Linux flight recorder: daemon → retroactive snapshot → `.bbx`
→ offline analysis. Product name: Blackbox; Go module:
`github.com/ebubekiryigit/blackbox-ebpf`.

## Architecture

- Go userspace and embedded C eBPF via cilium/ebpf/bpf2go, BTF and CO-RE.
- Static binary, foreground daemon, private Unix socket; no runtime compiler.
- Independent sensors aggregate normal activity in kernel and emit bounded details.
- One writer owns recorder state. Sealed time segments are immutable.
- Bound kernel maps, rings, ingress, metadata and retained history; expose loss.
- Keep domain/capture/analyzer independent of kernel access and control sockets.
- Best-effort is default. `--strict` fails on any enabled sensor initialization or
  permanent runtime failure. Persist incomplete coverage in captures.
- Record timing and metadata; no packet payloads, argv or environment. Findings
  cite observations and do not infer a root cause from timing alone.

## Adding features

Identify the owning layer first; follow `docs/development.md`. Keep the change
small and preserve capture compatibility. Ask the maintainer about significant
product/design choices, new runtime dependencies and changes to these boundaries.
Do not add future server, UI, database, profile or plugin abstractions speculatively.
The project, Go/userspace code and docs use Apache-2.0; preserve LICENSE.
BPF C/header sources use `SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only`.
Keep their separate ELF license declaration `GPL` for GPL-only kernel helpers.
Preserve LICENSES/GPL-2.0-only.txt and all third-party license/copyright notices.

Run behavioral checks relevant to the change: `make test`, `make vet`, and
`make build-linux`. Sensor changes also need `make generate` and Linux kernel
integration. Do not disrupt existing recordings or remote workloads for testing.

## Documentation and versions

Write concise operator/developer documentation in English. Describe current
behavior, runnable commands, limits and migration impact. Avoid conversational
notes, competitor references and full decision histories. Update affected docs
with the feature; keep general architecture in `docs/architecture.md`.

Bump the application build version in `internal/version/VERSION` only. Capture,
configuration and socket compatibility policy is published in
`docs/compatibility.md`; protocol discriminators remain independent of releases.
Local design notes under `.local/` are excluded from Git and Docker builds.

Operational defaults and bounds belong in `internal/config/defaults.go`; operators
receive validated configuration. Viper stays local to the config loader. Preserve
strict YAML v3 validation and defaults → file → explicit flags → validation.
Wire/schema invariants belong in model, not operator configuration.
The YAML format has no top-level version key. Do not add one without an actual
incompatible schema and migration design.

Keep Make, Docker/Compose, systemd, README, CLI help and config examples consistent.
After changing flags, defaults or Go version, run `make docs` and `make docs-check`.
After changing Go dependencies, run `make licenses` and review the generated bundle.
Sensor C changes also regenerate `bpf/abi.h` and embedded Go/ELF files together.
Preserve independent capture fixtures and the documented compatibility policy.
Before a release, compare the previous tag's defaults, config, CLI, capture reader,
socket protocol, persistence, resource use and rollback behavior with the new build.
Document operational changes even when wire formats are unchanged, especially new
background writes or retention. Follow the release checklist in
`docs/development.md`; keep the changelog, README, compatibility, security and
upgrade guidance consistent with the GitHub release description. Release
archives must carry project and runtime dependency licenses.

# Security

## Reporting a vulnerability

Report privately through this repository's **Security → Report a vulnerability**
form when GitHub Private Vulnerability Reporting is enabled. Include affected
versions, impact, a minimal reproduction and a proposed mitigation if available.
Do not post exploit details or sensitive captures in a public issue.

Before public release, the maintainer must enable private reporting or publish an
alternative private contact here. If the form is unavailable, ask the maintainer
for a private reporting channel without disclosing the vulnerability publicly.
There is no published response-time commitment during the development preview.

## Supported versions

Security fixes currently target the latest development revision. There are no
supported stable release branches yet. Upgrade instructions and independent capture,
config and socket compatibility contracts are in [docs/compatibility.md](docs/compatibility.md).

## Deployment and data boundaries

Recording currently requires root/BPF access; the supplied Compose service is
privileged and has host process visibility. Deploy only trusted builds and protect
configuration, binary and service files from untrusted writes. Offline analysis
requires neither root nor BPF access.

The control socket is in an owner-only directory and uses `0600` permissions.
Capture publication uses a temporary `0600` file, validates integrity and refuses
to overwrite. Archive decoding and control requests have explicit bounded size and
concurrency limits. Keep those bounds intact for untrusted inputs.

Blackbox collects timing and infrastructure metadata, including hostnames,
process identities, cgroup paths and network endpoints. It does not
collect packet payloads, process argv or environments. Captures are not encrypted;
use appropriate access control and secure transfer. A compressed `.bbx` file is
not anonymized. Do not commit incident captures or local deployment configuration.

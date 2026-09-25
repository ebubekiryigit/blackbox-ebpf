# Security

## Reporting a vulnerability

Report privately through this repository's **Security → Report a vulnerability**
form. GitHub Private Vulnerability Reporting is enabled. Include affected
versions, impact, a minimal reproduction and a proposed mitigation if available.
Do not post exploit details or sensitive captures in a public issue.

If the form is temporarily unavailable, ask the maintainer for a private contact
without disclosing the vulnerability publicly. There is no published response-time
commitment during the v0.2 preview.

## Supported versions

Security fixes target the latest v0.2 patch release and the current `main` branch.
Older preview patch releases are not maintained independently. Upgrade instructions
and config, capture, and socket compatibility contracts are in
[docs/compatibility.md](docs/compatibility.md).

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

Automatic incident files are enabled by default. They contain the same
sensitive metadata as manual captures. Automatic storage uses a private directory
and rotates its own reserved filenames within count/byte limits. Keep evidence that
must survive rotation outside that directory, and disable `auto_capture.enabled`
when unattended persistence is inappropriate. See [operations](docs/operations.md#automatic-incident-captures).

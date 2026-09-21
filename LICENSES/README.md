# Component licenses

The top-level [LICENSE](../LICENSE) contains Apache-2.0, the project license.

| Component | Source license |
| --- | --- |
| Go/userspace code, tools and documentation | Apache-2.0 |
| Project BPF C and header sources under `bpf/` | Apache-2.0 OR GPL-2.0-only |

Each project BPF source carries an SPDX header stating its dual-license terms.
The GPL-2.0-only license text is in [GPL-2.0-only.txt](GPL-2.0-only.txt).
The generated `bpf/abi.h` retains the same SPDX header through its generator.

The embedded BPF ELF programs declare `GPL` in `SEC("license")`. This is the
declaration consumed by the Linux loader/verifier for access to GPL-only helpers;
the source-code licensing terms are defined by the SPDX headers. This kernel
declaration does not change the Apache-2.0 license of the Go/userspace program.

Third-party dependencies retain their own licenses and copyright notices.
Preserve those notices unchanged when copying or modifying third-party material.
The generated [third-party bundle](../third_party/README.md) preserves dependency
licenses and notices. Runtime containers include this material under
`/usr/share/licenses/blackbox/`; binary release archives include the same reviewed
bundle alongside the project licenses.

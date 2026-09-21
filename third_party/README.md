# Third-party notices

`licenses/` contains license and notice files required by the Go dependencies
linked into the Linux Blackbox binary. The files are generated with the pinned
`go-licenses` version in `scripts/licenses.sh`. The reviewed bundle is copied into
the runtime container and every binary release archive, so each distributed
artifact carries its own notices without a separate download.

Run `make licenses` after changing Go dependencies, review the resulting files,
and commit them with `go.mod` and `go.sum`. `make licenses-check` fails when the
checked-in bundle does not match the Linux dependency graph.

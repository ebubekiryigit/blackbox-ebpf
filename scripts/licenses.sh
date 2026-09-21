#!/bin/sh
set -eu

mode=${1:-check}
go_command=${GO:-go}
destination=third_party/licenses
temporary=$(mktemp -d "${TMPDIR:-/tmp}/blackbox-licenses.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

(cd tools/licenses && "$go_command" build -mod=readonly -o "$temporary/go-licenses" github.com/google/go-licenses/v2)
module=$($go_command list -m)
GOOS=linux GOARCH=amd64 "$temporary/go-licenses" save ./cmd/blackbox \
  --ignore "$module" --save_path "$temporary/licenses"

case "$mode" in
  generate)
    rm -rf "$destination"
    mkdir -p "$(dirname "$destination")"
    cp -R "$temporary/licenses" "$destination"
    ;;
  check)
    diff -ru "$destination" "$temporary/licenses"
    ;;
  *)
    echo "usage: $0 [generate|check]" >&2
    exit 2
    ;;
esac

#!/bin/sh
set -eu

go_command=${GO:-go}
version=$(tr -d '[:space:]' < internal/version/VERSION)
tag="v$version"
destination=dist
temporary=$(mktemp -d "${TMPDIR:-/tmp}/blackbox-release.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

if ! printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
  echo "invalid semantic version: $version" >&2
  exit 1
fi

rm -rf "$destination"
mkdir -p "$destination"

for architecture in amd64 arm64; do
  package="blackbox-${tag}-linux-${architecture}"
  root="$temporary/$package"
  mkdir -p "$root/LICENSES" "$root/third_party"

  CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" "$go_command" build \
    -trimpath -ldflags '-s -w' -o "$root/blackbox" ./cmd/blackbox

  cp README.md CHANGELOG.md config.example.yml "$root/"
  cp deploy/blackbox.service "$root/blackbox.service"
  cp LICENSE "$root/"
  cp LICENSES/GPL-2.0-only.txt LICENSES/README.md "$root/LICENSES/"
  cp third_party/README.md "$root/third_party/"
  cp -R third_party/licenses "$root/third_party/licenses"

  COPYFILE_DISABLE=1 tar -C "$temporary" -czf "$destination/$package.tar.gz" "$package"
  rm -rf "$root"
done

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$destination" && sha256sum ./*.tar.gz > checksums.txt)
else
  (cd "$destination" && shasum -a 256 ./*.tar.gz > checksums.txt)
fi

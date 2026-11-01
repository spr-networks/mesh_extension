#!/bin/bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
BIN=$(mktemp -d)
trap 'rm -rf "$BIN"' EXIT

case "$(docker info --format '{{.Architecture}}')" in
  aarch64|arm64) GOARCH=arm64 ;;
  x86_64|amd64) GOARCH=amd64 ;;
  *) echo "unsupported docker architecture" >&2; exit 1 ;;
esac

(cd "$REPO/code" && CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -o "$BIN/mesh" .)
docker build -q -t spr-macsec-e2e "$HERE" >/dev/null

SCRIPT=${1:-macsec_e2e.sh}
docker run --rm -v "$REPO":/repo:ro -v "$BIN":/e2e-bin:ro spr-macsec-e2e bash -c \
  "cd /tmp && vng --run /boot/Image --disable-kvm --force-9p --user root --cpus 2 --memory 1G --exec 'REPO=/repo MESH=/e2e-bin/mesh bash /repo/tests/e2e/$SCRIPT'" \
  | tee "$BIN/e2e.log"
grep -q "E2E CHECKS PASSED" "$BIN/e2e.log"

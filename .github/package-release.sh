#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."

targets=(
  linux/amd64
  linux/arm64
  linux/386
  linux/arm
  darwin/amd64
  darwin/arm64
  windows/amd64
  windows/arm64
)

rm -rf dist
mkdir -p dist

for target in "${targets[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  ext=""
  label="$arch"
  if [ "$os" = "windows" ]; then
    ext=".exe"
  fi
  if [ "$arch" = "arm" ]; then
    label="armv7"
  fi

  stage="$(mktemp -d)"
  if [ "$arch" = "arm" ]; then
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOARM=7 go build -ldflags="-s -w" -o "$stage/yellowdns$ext" .
  else
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w" -o "$stage/yellowdns$ext" .
  fi
  cp GeoLite2-Country.mmdb "$stage/"

  archive="yellowdns_${os}_${label}.zip"
  (
    cd "$stage"
    zip -q "$archive" "yellowdns$ext" GeoLite2-Country.mmdb
  )
  mv "$stage/$archive" dist/
  rm -rf "$stage"
  echo "packed dist/$archive"
done

if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum ./*.zip > SHA256SUMS)
else
  (cd dist && shasum -a 256 ./*.zip > SHA256SUMS)
fi
echo "packed $(find dist -name '*.zip' | wc -l | tr -d ' ') archives"

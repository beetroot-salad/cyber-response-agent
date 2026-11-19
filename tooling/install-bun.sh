#!/bin/sh
# The one Bun install (#1540 F6): the pinned release, its sha256 checked before it is unpacked, installed as
# /usr/local/bin/bun. CI's test and lint jobs and the dev image run this file and download Bun nowhere else, so a
# Bun bump edits the two lines below. Needs curl, sha256sum and unzip, and root (or sudo) to write /usr/local/bin.
set -eu
BUN_VERSION=1.4.4
BUN_SHA256=bf8ccbfb2b0b80159e0f9a6d15c55317add8077534dbc6130a3edb52fccb395c

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 2 -o "$work/bun.zip" "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-x64.zip"
echo "${BUN_SHA256}  $work/bun.zip" | sha256sum -c -
unzip -q "$work/bun.zip" -d "$work"
install -m 0755 "$work/bun-linux-x64/bun" /usr/local/bin/bun
bun --version

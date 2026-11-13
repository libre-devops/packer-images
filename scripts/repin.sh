#!/usr/bin/env bash
# Brings every pin up to date with the version it pins: each tool's SHA-256
# and Python lock after a version bump in tools/tools.yml, each image's audit
# content after a lockdown role bump in its image.yml, and the image READMEs.
# What a Renovate pull request needs before it can build; the Pins workflow
# runs it there. A pin that is already for its version is left alone.
#
# Usage: scripts/repin.sh   (needs `just deps` first)

set -euo pipefail

repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
# The pinned Packer (`just tools`) and the locked Python tools (`just deps`).
export PATH="$repo/.tools/bin:$repo/.venv/bin:$PATH"
images=(uv run --quiet --no-sync "$repo/scripts/images.py")

"${images[@]}" pin-tools
"${images[@]}" pin-audit
"${images[@]}" docs

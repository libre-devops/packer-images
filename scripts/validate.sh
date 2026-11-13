#!/usr/bin/env bash
# Runs `packer validate` for every target of an image, with variables rendered
# exactly as a build renders them.
#
# Usage: scripts/validate.sh <image>

set -euo pipefail

image=${1:?usage: validate.sh <image>}
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
# The pinned Packer (`just tools`) and the locked Python tools (`just deps`).
export PATH="$repo/.tools/bin:$repo/.venv/bin:$PATH"
images=(uv run --quiet --no-sync "$repo/scripts/images.py")

workdir=$(mktemp -d)
trap 'rm -rf -- "$workdir"' EXIT
ssh-keygen -q -t ed25519 -N '' -f "$workdir/key"

packer init "$repo/images/$image" >/dev/null
for target in $("${images[@]}" targets "$image"); do
	"${images[@]}" render "$image" "$target" --workdir "$workdir" --output "$workdir/out" --ssh-key "$workdir/key"
	packer validate -only="$image.$target.image" -var-file="$workdir/build.pkrvars.json" "$repo/images/$image"
done

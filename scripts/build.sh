#!/usr/bin/env bash
# Builds one image for one target, into output/<image>/<target>.
#
# Usage: scripts/build.sh <image> [target]   (target defaults to qemu)
#
# Makes an SSH key for this build only, renders the pinned inputs and the
# hardening profile from image.yml, runs Packer, then records what the image
# was built from next to it. Needs `just tools deps` first.

set -euo pipefail

image=${1:?usage: build.sh <image> [target]}
target=${2:-qemu}

repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
# The pinned Packer (`just tools`) and the locked Python tools (`just deps`).
export PATH="$repo/.tools/bin:$repo/.venv/bin:$PATH"
out="$repo/output/$image/$target"
images=(uv run --quiet --no-sync "$repo/scripts/images.py")

workdir=$(mktemp -d)
trap 'rm -rf -- "$workdir"' EXIT

ssh-keygen -q -t ed25519 -N '' -C "packer-build-$image" -f "$workdir/build_key"
"${images[@]}" render "$image" "$target" --workdir "$workdir" --output "$out" --ssh-key "$workdir/build_key"

# Packer refuses to write over an earlier build.
rm -rf -- "$out"
mkdir -p -- "$(dirname -- "$out")"

export PACKER_CACHE_DIR="$repo/.cache/packer"
export ANSIBLE_CONFIG="$repo/ansible.cfg"
packer init "$repo/images/$image"
packer build \
	-only="$image.$target.image" \
	-var-file="$workdir/build.pkrvars.json" \
	"$repo/images/$image"

cp -- "$workdir/image.json" "$workdir/hardening.yml" "$out/"
echo "Built $out" >&2

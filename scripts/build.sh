#!/usr/bin/env bash
# Builds one image for one target, into output/<image>/<target>.
#
# Usage: scripts/build.sh <image> [target]   (target defaults to qemu)
#
# Makes an SSH key for this build only, renders the pinned inputs and the
# hardening profile from image.yml, runs Packer, then records what the image
# was built from next to it. Needs `just tools deps` first.
#
# The playbooks retry each network operation themselves. If the build still
# fails, it runs again from the start, BUILD_ATTEMPTS times in all (default
# 2), so one failure that nothing else caught does not fail the pipeline. Set
# BUILD_ATTEMPTS=1 to stop at the first failure while debugging. Ctrl-C stops
# it without another attempt.

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

export PACKER_CACHE_DIR="$repo/.cache/packer"
export ANSIBLE_CONFIG="$repo/ansible.cfg"
"$repo/scripts/retry.sh" 3 20 packer init "$repo/images/$image"

trap 'echo "build.sh: interrupted" >&2; exit 130' INT TERM
attempts=${BUILD_ATTEMPTS:-2}
for ((attempt = 1; ; attempt++)); do
	# Packer refuses to write over an earlier build, or a failed attempt.
	rm -rf -- "$out"
	mkdir -p -- "$(dirname -- "$out")"
	status=0
	packer build \
		-only="$image.$target.image" \
		-var-file="$workdir/build.pkrvars.json" \
		"$repo/images/$image" || status=$?
	if ((status == 0)); then
		break
	fi
	if ((attempt >= attempts)); then
		echo "build.sh: the build of $image ($target) failed $attempts times" >&2
		exit "$status"
	fi
	echo "build.sh: attempt $attempt of $attempts failed (exit $status); building again from the start in 60s" >&2
	sleep 60
done

cp -- "$workdir/image.json" "$workdir/hardening.yml" "$out/"
echo "Built $out" >&2

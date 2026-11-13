# Libre DevOps Packer images. Run `just` to list the recipes.
#
# CI runs these same recipes, so a local run shows what CI will do. You need uv
# (https://docs.astral.sh/uv/), git, gpg, QEMU with KVM, the ovmf package and
# xorriso. Install just with `uv tool install rust-just`.

set shell := ["bash", "-euo", "pipefail", "-c"]

images := "uv run --quiet --no-sync scripts/images.py"

# Pinned tools land here; every recipe puts them first on PATH.
export PATH := justfile_directory() / ".tools/bin:" + justfile_directory() / ".venv/bin:" + env_var("PATH")

# List the recipes.
default:
    @just --list

# List the images.
images:
    @{{ images }} list

# List an image's targets (its Packer source types): just targets ubuntu-24.04
targets image:
    @{{ images }} targets '{{ image }}'

# Install the pinned Packer, checking HashiCorp's signature and the SHA-256.
tools:
    uv run --quiet scripts/images.py tools

# Install the Python tools and collections, and fetch every image's pinned role and audit content.
deps:
    uv sync --locked --quiet
    uv run --no-sync ansible-galaxy collection install -r requirements.yml -p .ansible/collections
    {{ images }} deps

# Pin each image's audit content to the commit that matches its role release (after a role bump): just pin-audit ubuntu-24.04
pin-audit *images: deps
    {{ images }} pin-audit {{ images }}

# Pin the tools in tools/tools.yml (after a Renovate bump): each archive's SHA-256, checked against the vendor's checksums, and each Python tool's hash-locked requirements: just pin-tools uv
pin-tools *tools: deps
    {{ images }} pin-tools {{ tools }}

# Bring every pin up to date with its version, as a Renovate pull request needs: tool SHA-256s and Python locks, audit content and READMEs. The Pins workflow runs it on Renovate's branches.
repin: deps
    scripts/repin.sh

# For the Pins workflow: commit what `just repin` changed to a pull request's branch, signed by GitHub, and start the checks on it.
push-pins branch:
    scripts/push-pins.sh '{{ branch }}'

# Write each image's README from its image.yml, hardening files and exceptions.
docs:
    {{ images }} docs

# List the CIS exception registry, soonest review first. EXCEPTIONS_TODAY=2027-05-01 shows what will be due then.
exceptions:
    @{{ images }} exceptions

# Lint YAML, playbooks (ansible-lint, production profile), shell scripts, Packer formatting and workflows.
lint: deps
    uv run --no-sync yamllint .
    uv run --no-sync ansible-lint
    shellcheck -S warning scripts/*.sh
    packer fmt -check -recursive -diff images
    uv run --no-sync zizmor --offline .github/workflows

# Check every image definition, hardening profile and exception, that the image READMEs are current, then `packer validate` each image.
validate: tools deps
    {{ images }} validate
    {{ images }} docs --check
    for image in $({{ images }} list); do scripts/validate.sh "$image"; done

# Build an image for a target, into output/<image>/<target>: just build ubuntu-24.04
build image target="qemu": tools deps
    scripts/build.sh '{{ image }}' '{{ target }}'

# Boot a built image as a new VM, check it, and run the CIS audit gate: just test ubuntu-24.04
test image target="qemu": deps
    scripts/test.sh '{{ image }}' '{{ target }}'

# Build, then test.
all image target="qemu": (build image target) (test image target)

# Re-run the audit gate on the last test's report, for example after editing exceptions.yml.
gate image target="qemu":
    {{ images }} gate '{{ image }}' '{{ target }}' "$(find 'output/{{ image }}/{{ target }}/audit' -maxdepth 1 -name '*.json' -print -quit)" --summary 'output/{{ image }}/{{ target }}/audit/summary.md'

# Scan the full git history for secrets (needs gitleaks on PATH).
secrets:
    gitleaks git --redact --verbose .

# Delete build output, or one image's: just clean ubuntu-24.04
clean image="":
    rm -rf -- 'output/{{ image }}'

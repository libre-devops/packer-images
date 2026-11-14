# Contributing

Issues and pull requests are welcome. Open an issue first for anything large, such as a new image or target, so we can agree the approach before you write it.

## Set up

You need [uv](https://docs.astral.sh/uv/), [just](https://github.com/casey/just), git, gpg, and for building and testing, QEMU with KVM, the `ovmf` UEFI firmware and `xorriso`. On Ubuntu or Debian:

```bash
sudo apt-get install qemu-system-x86 qemu-utils ovmf xorriso
sudo usermod -aG kvm "$USER"   # then log in again
```

Then:

```bash
just tools      # the pinned Packer, signature checked
just deps       # Python tools, collections, every image's pinned role and audit content
just lint       # yamllint, ansible-lint (production profile), shellcheck, packer fmt, zizmor
just validate   # image definitions, hardening profiles, packer validate
just all ubuntu-24.04   # build, boot as a new VM, check, audit and gate
```

## Rules

- **Ansible configures, Packer builds.** Everything that changes the guest is an Ansible playbook or role. A Packer template only says where to build (its sources) and which playbooks to run.
- **Pin third-party content, never copy it in.** Roles, audit content, ISOs and tools are pinned in `images/<name>/image.yml` or `versions.yml`, to a release and the commit it must point at where there is one. `just deps` refuses a tag that has moved.
- **Every hardening deviation is data with a reason.** Change the role's behaviour only through `images/<name>/hardening/common.yml` or the target's file, one entry per variable, each with a `reason`. Never pass `-e` or `--skip-tags` from a template or script. `just validate` refuses an entry with no reason or a variable the pinned role does not have.
- **Every CIS control an image does not meet is an exception in [`exceptions.yml`](./exceptions.yml)**, whether the audit fails it or a setting switches it off. The gate fails the build on any failure no exception covers. See [Record an exception](#record-an-exception).
- **Generic values only.** Nothing from any organisation's environment: no host names, domains, proxies, internal mirrors or naming conventions.
- Docs and comments are in British English, with no em or en dashes.

## When Renovate bumps a lockdown role

1. The Pins workflow runs `just repin` on its branch, which moves the audit content to the last commit before the new release, commits it to the branch and starts the checks. On a branch from a fork, run `just repin` yourself and commit the result.
2. Run `just validate`. A role release can rename or remove variables, and validation names any setting in `hardening/` that no longer exists.
3. Let the image's pipeline build, test and audit the branch. If new failures appear, fix the image or accept them with a reason, and run `just docs`.

To look around a test VM, run `KEEP=1 just test <image>`: it leaves the VM running and prints the SSH command.

## Record an exception

When the gate reports a control no exception covers, first try to fix the image. If the image should not meet the control, or the control is one the audit cannot check:

If a control stops something the images exist to do, such as running containers, do not apply it and then work around it: switch it off in the hardening profile with an exception, kind `deviation`, whose reason says what it breaks and how you proved it on a test VM (`KEEP=1 just test <image>`). Add it to the table under "Hardening skipped so the images work" in the README.

1. Look in [`exceptions.yml`](./exceptions.yml) for an entry on the same subject from another image, such as the bootloader password. If the same decision applies, add your image and its control number to that entry's `controls`. Numbers differ between benchmarks, so check the image's own audit output.
2. Otherwise add an entry with the next free id. Use `kind: manual` for a control the benchmark marks as manual, and give as the `reason` what you checked on a test VM (`KEEP=1 just test <image>`), not what the image probably does. Use `kind: false-positive` only when you have read the audit check and can say why it is wrong, with what the image actually does; consider reporting it to the lockdown team. Use `kind: deviation` for anything else, with a `mitigation`.
3. If the image switches the control off in the role (a `<prefix>_rule_<number>: false` setting), give that setting `exception: EX-<id>` instead of a reason.
4. Set `decided_by`, `decided_on` (today) and `review_by` (six months is usual, a year at most), then run `just validate`, `just docs` and `just gate <image>`.

The gate also fails when an entry covers a control that now passes, for example after a role bump. Take the control out of the entry, or retire the entry (`status: retired`, `retired_on`, `retired_reason`) if it covers nothing else. Retire rather than delete, so the decision stays on record.

When `just validate` warns that a review is due, decide again: if the reason still holds, set `decided_on` to the day and a new `review_by` in one pull request, with the decision in its description.

## Bump an installer ISO

Renovate cannot bump ISOs, so do it by hand when a point release comes out:

1. Find the new file and its SHA-256 in the vendor's signed checksums, and check the signature. For Ubuntu, `SHA256SUMS` and `SHA256SUMS.gpg` under `releases.ubuntu.com/<version>/`. For AlmaLinux, the clear-signed `CHECKSUM` under `repo.almalinux.org/almalinux/<version>/isos/x86_64/`, against the AlmaLinux 9 key (fingerprint `BF18 AC28 7617 8908 D6E7 1267 D36C B86C B86B 3716`).
2. Update both URLs and `sha256` under `iso` in `image.yml`.
3. Run `just all <image>` and attach the audit summary to the pull request.

## Add an image

1. Copy the closest image (`images/ubuntu-24.04` or `images/rhel-9`) to `images/<name>` and change `image.yml`: ISO, ansible-lockdown role and audit content, each with its commit.
2. Write the installer answers for the target (autoinstall, kickstart or an answer file).
3. Start `hardening/common.yml` from the role's defaults, with an entry and reason for each change, and run `just pin-audit <name>`. Read the role's defaults for anything that depends on the connecting user: the build account is deleted, so a setting that allows only that user locks everyone out.
4. Copy `.github/workflows/ubuntu-24.04.yml` to `<name>.yml` and change the image name and paths.
5. Add the image to the table in `README.md`, run `just docs`, then `just all <name>`, and record an exception for each failure you do not fix.

## Add a tool

1. If the tool is not in `tools/tools.yml`, add it under `tools`, picking the method that fits:
   - `package` when the base images' own repositories have it, with the package names for `Debian` and `RedHat`. This is the first choice: the OS vendor signs and patches it.
   - `archive` for a release archive: `url` and, where the vendor publishes them, `checksums`, both with `{version}`, and `files`, each command and its path in the archive. Leave `sha256` empty.
   - `python` for a PyPI application: `package`, `requires: [python, uv]`, and its `commands`, or `modules` for one whose script would pick up any Python on PATH.
   - `tenv` for a Terraform or OpenTofu version, with `requires: [tenv]`.
   - `directory` for a directory a group shares, with `path` under `/opt`, `group`, the `members` allowed to write by account name, and `requires: [acl]`.

   Each method's tasks retry their network operations, so a new method must as well (`until`, `retries`, `delay`).

   Give a versioned tool a `# renovate:` comment on the line above `version`, with the datasource and name, so Renovate bumps it. Give it a `check`, a command that prints its version, which the test runs as an unprivileged user. Put any environment variable it needs under `environment`.
2. Run `just pin-tools <tool>`. It writes the archive's SHA-256 after checking it against the vendor's checksums, or the Python tool's hash-locked requirements in `tools/locks/`.
3. Add its name to `tools` in each image's `image.yml` that needs it. What it requires comes with it.
4. Run `just validate`, `just docs` and `just all <image>`, and attach the audit summary to the pull request.

When Renovate bumps a tool, the Pins workflow ([`pins.yml`](./.github/workflows/pins.yml)) runs `just repin` on its branch: it pins the new SHA-256 against the vendor's checksums or relocks the Python tool, pushes that to the branch as `github-actions[bot]`, and starts the checks on it. Nobody edits a hash by hand. On a branch from a fork, run `just repin` yourself. Either way, the build refuses an archive that does not match its pin, and `just validate` refuses a lock or a SHA-256 pinned for another version.

## Add a role image

1. Create `images/<name>` with an `image.yml` that names its `base`, a golden image, and lists its `tools`, and no `iso` or `hardening`. Copy the Packer files from `images/azdo-agent-ubuntu-24.04` and change the names.
2. Copy `.github/workflows/azdo-agent-ubuntu-24.04.yml` to `<name>.yml` and change the image, base and paths. The job builds the base first.
3. Add the image to the table in `README.md`, run `just docs`, then `just build <base>` and `just all <name>`. The base's exceptions apply; record one for the role image only for a failure that comes from its tools.

## Add a target

Add a source file to the image (for example `azure-arm.pkr.hcl`) named `image`, add it to `sources` in `build.pkr.hcl`, and add `hardening/<source type>.yml`. `just validate` refuses a source with no hardening file.

## Commits and versions

Write commit subjects in the imperative, wrapped at 72 characters, with a body only when the change needs explaining. No trailers of any kind. Add an entry under Unreleased in `CHANGELOG.md`.

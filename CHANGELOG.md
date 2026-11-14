# Changelog

Notable changes to these images and their build. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

- Ubuntu 24.04 LTS golden image for the QEMU target: installed from the pinned ISO with UEFI and an LVM layout that gives each path CIS asks for its own volume, patched, hardened to CIS Level 1 Server with ansible-lockdown UBUNTU24-CIS, and generalised.
- Pins for every third-party input in `images/<name>/image.yml` and `versions.yml`: ISO, lockdown role (tag and commit), audit content (commit), Packer (signature checked against HashiCorp's key).
- Hardening profiles as data, `hardening/common.yml` plus one file per target, where every deviation from the role's defaults has a reason, checked by `just validate` against the pinned role.
- A test that boots the finished image as a new VM with a cloud-init seed, checks it was generalised and that no unit failed, runs the pinned audit through the lockdown role, and gates the result on the exception registry.
- A justfile whose recipes CI runs, a reusable image workflow with one calling workflow per image, and Renovate for the pins.
- `just pin-audit`, which pins an image's audit content to the last commit before its role release, and a check in `just deps` that refuses newer audit content, because the audit branch runs ahead of the role.
- `just docs`, which writes each image's README (pins, changes to the role's defaults, exceptions) from its files and the registry, checked by `just validate`.
- `KEEP=1 just test <image>`, which leaves the test VM running for debugging.
- RHEL 9 golden image (`rhel-9`) for the QEMU target, installed from the AlmaLinux 9.8 minimal ISO with a kickstart, patched, and hardened to CIS Red Hat Enterprise Linux 9 v2.0.0 Level 1 Server with ansible-lockdown RHEL9-CIS 2.4.2, with its own workflow.
- The CIS exception registry, `exceptions.yml`: every control an image does not meet, as a decision with a kind (`deviation`, `manual` or `false-positive`), risk, reason, mitigation, owner, decision date and review date. `just validate` checks each entry and checks it against the images and their pinned roles. The gate fails on any failure no entry covers, on an entry whose control now passes, on a review that is overdue, and on findings beyond what an entry accepts. `just exceptions` lists the registry.
- The harden step blocks every filesystem kernel module an image does not use or keep, and sets the services the default firewall zone allows where the profile lists them (`firewall_services`), two controls the lockdown roles only report on.
- Each VM re-initialises AIDE on its first boot, so its database describes the VM rather than the build.
- Role images: an image can name a golden image as its `base` and add tools. It starts from the base's finished disk, keeps its hardening, and is audited with the base's gate and exceptions. `azdo-agent-ubuntu-24.04` is the first, for Azure DevOps scale set agents, with its own workflow.
- The tool catalogue, `tools/tools.yml`, with four install methods (distribution packages, SHA-256 pinned release archives, Python applications in their own environments from hash-locked requirements, and Terraform through tenv), `just pin-tools`, and Renovate for the versions. The test runs each tool as an unprivileged user and checks the pinned version.
- Podman, with the docker command, in both golden images, installed before the harden step.
- `azdo-agent-rhel-9`, the same Azure DevOps agent image on `rhel-9`, with its own workflow.
- `gh-runner-ubuntu-24.04` and `gh-runner-rhel-9`, GitHub Actions self-hosted runner images with the same tools and the runner pinned at `/opt/actions-runner`, checked against its release notes and GitHub's digest. An archive tool can now unpack whole (`extract_to`), and every pin of a GitHub release asset is also checked against GitHub's recorded SHA-256.
- A shared tool cache, `/opt/hostedtoolcache`, in the agent and runner images, for the pipelines' setup tasks: owned by root and the `toolcache` group, setgid, with default ACLs, writable only by the accounts that run jobs (listed by name), where Microsoft's images make it world-writable. A `directory` method in the catalogue, and `expect` can list several strings.
- `just secrets` installs the pinned gitleaks into `.tools`, checked against its release's checksums and GitHub's digest, and CI's secret scan runs it, instead of an inline download step.
- The test copies goss, the audit binary, from the build host, where `just deps` downloads it with retries and checks it against the lockdown role's pinned SHA-256, instead of the VM downloading it.
- Retries on every network operation: Ansible's package, download and install tasks, apt's downloads (kept in the Ubuntu images), `images.py`'s downloads and git fetches, `packer init`, and the build itself once more from the start (`BUILD_ATTEMPTS`), so one failure does not fail a pipeline.
- The Pins workflow: on Renovate's pull requests it runs `just repin`, which pins each new tool version's SHA-256 or Python lock and each new role's audit content, commits that to the branch as one commit GitHub signs, starts the checks on it, and deletes the runs GitHub holds for approval for that commit. The repository allows only squash merges.

### Changed

- Accepted audit failures moved from each image's `hardening/accepted.yml` into the registry, and the five decisions open on 9 November 2026 are recorded there or in the build: no bootloader password in the image (EX-001), only the filesystem modules the image needs stay loadable (EX-002), and AIDE re-initialises on first boot. Images stay unpublished for now.
- A setting that switches a CIS control off must name its exception, and one that switches off a whole section is refused.
- The test seed gives its user a sudo rule rather than an admin group, so it works on every family.
- The finalise script also removes the random seed and the DNF cache.
- Both golden images keep the overlay module loadable for podman (EX-002, decided again on 13 November 2026).
- CIS controls that stop the images running containers are not applied, and are listed in the README: `ubuntu-24.04` does not apply 1.3.1.3, which moves every AppArmor profile into complain mode, in which no container runs (EX-018). Package tools install without recommends on Debian.
- The finalise script removes the sudo rule cloud-init writes for the build account, and the test checks no sudo rule names it.
- `ubuntu-24.04` allows SSH out as well as DNS, HTTP, HTTPS and NTP, so git and Ansible work over SSH, and the agent image's test checks it reaches github.com on port 22.

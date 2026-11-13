<div align="center">
  <a href="https://libredevops.org">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://libredevops.org/assets/libre-devops-white.png">
      <img alt="Libre DevOps" src="https://libredevops.org/assets/libre-devops-black.png" width="300">
    </picture>
  </a>
</div>

# Packer images

Golden VM images built with Packer and configured with Ansible. Each image is installed from a pinned vendor ISO, patched, hardened to a CIS benchmark with the matching [ansible-lockdown](https://github.com/ansible-lockdown) role, generalised, and then booted as a new VM and audited. Every CIS control an image does not meet is a decision in one registry, [`exceptions.yml`](./exceptions.yml), with a reason, a risk and a review date, and any audit failure the registry does not cover fails the build.

[![CI](https://github.com/libre-devops/packer-images/actions/workflows/ci.yml/badge.svg)](https://github.com/libre-devops/packer-images/actions/workflows/ci.yml)
[![ubuntu-24.04](https://github.com/libre-devops/packer-images/actions/workflows/ubuntu-24.04.yml/badge.svg)](https://github.com/libre-devops/packer-images/actions/workflows/ubuntu-24.04.yml)
[![rhel-9](https://github.com/libre-devops/packer-images/actions/workflows/rhel-9.yml/badge.svg)](https://github.com/libre-devops/packer-images/actions/workflows/rhel-9.yml)
[![Licence](https://img.shields.io/github/license/libre-devops/packer-images)](./LICENSE)

---

> **Status:** both images build, boot as a new VM and pass their audit gate under QEMU with KVM, run locally on 13 November 2026. `ubuntu-24.04`: 591 audit checks, 582 passed, 1 skipped and 8 failed. `rhel-9`: 622 checks, 608 passed, 3 skipped and 11 failed. Every failure is covered by an exception in the registry, and each VM built its own AIDE database on first boot. The GitHub Actions workflows have not run yet, because the repository is not on GitHub yet. No images are published, and there are no cloud targets yet.

## Images

| Image | Targets | Hardening | Pipeline |
|---|---|---|---|
| [`ubuntu-24.04`](./images/ubuntu-24.04) | `qemu` | CIS Ubuntu Linux 24.04 LTS v1.0.0, Level 1 Server, with [UBUNTU24-CIS](https://github.com/ansible-lockdown/UBUNTU24-CIS) | [`ubuntu-24.04.yml`](./.github/workflows/ubuntu-24.04.yml) |
| [`rhel-9`](./images/rhel-9) | `qemu` (AlmaLinux 9) | CIS Red Hat Enterprise Linux 9 v2.0.0, Level 1 Server, with [RHEL9-CIS](https://github.com/ansible-lockdown/RHEL9-CIS) | [`rhel-9.yml`](./.github/workflows/rhel-9.yml) |

The `rhel-9` image's QEMU target installs AlmaLinux 9, which is built from the same sources as RHEL 9 and which RHEL9-CIS supports, because the RHEL ISO needs a Red Hat login and a subscription to patch. The work to build it from RHEL itself is in [`docs/rhel.md`](./docs/rhel.md). Its cloud targets, when they come, will start from Red Hat's own images.

Planned, in this order: Windows Server 2025 and Windows 11 as golden images, each hardened with its ansible-lockdown role (Windows-2025-CIS, Windows-11-CIS). Then role images built on top of them, such as Azure DevOps agents and Azure Virtual Desktop hosts. Then the Azure Compute Gallery and AWS AMI targets.

## How a build works

Every image goes through the same steps. Packer only starts the VM and runs the playbooks; Ansible does all the configuration.

| Step | Where | What it does |
|---|---|---|
| Install | the image's `qemu.pkr.hcl`, with `autoinstall/` (Ubuntu) or `kickstart/` (Red Hat family) | Boots the pinned ISO with UEFI and installs unattended, with an LVM volume for each path CIS asks to be its own partition. Creates a build account with an SSH key made for this build only and a random password used only for `sudo`. |
| Base | [`ansible/base.yml`](./ansible/base.yml) | Waits for first boot, applies every update, adds cloud-init where the installer did not and the target's guest agent, and reboots into the upgraded system. |
| Harden | [`ansible/harden.yml`](./ansible/harden.yml) | Runs the pinned lockdown role with the image's hardening profile and the profile's tag, such as `level1-server`. Then blocks every filesystem kernel module the image does not use or keep, and sets the firewall services the image allows, where the profile lists them: two controls the lockdown roles only report on. |
| Generalise | [`ansible/generalise.yml`](./ansible/generalise.yml) | Removes the installer's logs and copies of its answers, and its cloud-init and network configuration. Cleans the package cache, sets AIDE to make a new database on each VM's first boot, and installs the finalise script. |
| Finalise | Packer's shutdown command | Deletes the build account, resets cloud-init, the machine ID, the SSH host keys and the random seed, empties the logs, trims free space and powers off. Packer then compresses the disk and writes its SHA-256. |
| Test | [`scripts/test.sh`](./scripts/test.sh), [`ansible/verify.yml`](./ansible/verify.yml) | Boots the image on a throwaway overlay disk with a cloud-init seed, as a platform would start a VM. Checks the first boot succeeded with no failed units, AIDE made the VM's own database, and nothing of the build is left. Then runs the pinned audit content through the lockdown role's audit-only mode. |
| Gate | `scripts/images.py gate` | Checks the audit report against the exception registry (see [Exceptions](#exceptions)) and writes `audit/summary.md`. |

```text
pinned ISO ─► install ─► base ─► harden ─► generalise ─► finalise ─► qcow2 + SHA-256
   ─► boot as a new VM ─► check generalised ─► audit ─► gate
```

The output lands in `output/<image>/<target>/`:

| File | What it is |
|---|---|
| `<image>.qcow2` | The image, compressed. |
| `image.sha256` | The SHA-256 of the image and of `efivars.fd`. |
| `efivars.fd` | The UEFI variables from the build. You do not need them: the image boots with fresh UEFI variables, which is how the test boots it. |
| `image.json` | Exactly what it was built from: the ISO, the role tag and commit, the audit commit, the profile, every setting with its reason, the exceptions that applied, and this repository's commit. |
| `hardening.yml` | The hardening variables the role ran with. |
| `packer-manifest.json` | Packer's build manifest. |
| `audit/` | The goss report, the gate's summary and the test VM's console log. |

## Hardening

Each image's `hardening/` folder is the whole record of how it applies its lockdown role:

- `common.yml` holds the CIS profile, as the role tag that selects it, every setting that differs from the role's defaults, and which filesystem kernel modules stay loadable. Each setting has a reason.
- `<target>.yml`, one per Packer source type, adds or overrides settings for that target only. Cloud images cannot have the separate partitions an ISO install gives, for example.

`just validate` refuses a setting with no reason, a duplicate, or a variable the pinned role does not have, so a variable renamed in a new role release cannot silently stop applying. It also refuses a setting that switches a CIS control off without naming its exception, and one that switches off a whole section. The audit checks the controls the role was asked to apply, because the role writes the audit's variables from its own, so a control switched off silently would also vanish from the audit.

Each image's README, such as [`images/rhel-9`](./images/rhel-9), lists its pins, its changes to the role's defaults and its exceptions. `just docs` writes it from the files above and the registry, and `just validate` fails if it is out of date.

## Exceptions

[`exceptions.yml`](./exceptions.yml) is the one registry of CIS controls the images do not meet. Each entry is a decision: what the exception is, whether it is a deliberate `deviation`, a `manual` control the audit cannot check, or a `false-positive` where the pinned audit check is wrong for the image, its risk, the reason, what mitigates it, which controls it covers on which images, who decided, when, and when it must be reviewed. An entry covers one subject across images, because the same decision usually applies to each, under each benchmark's own control numbers.

The registry is checked twice:

| When | Check | Fails on |
|---|---|---|
| `just validate`, on every change | Each entry on its own | A missing field, an unknown kind, risk or status, a review date more than a year after the decision or already past, or a duplicate id. |
| | Each entry against the images | An image or target that does not exist, a control the pinned lockdown role does not have (so a renumbered benchmark is caught on the role bump), or a control two entries both cover. |
| | Each image's hardening files against the registry | A setting that switches a control off without naming an entry that covers it, or kept filesystem modules that differ from their entry's `findings`. |
| The gate, after every test | The audit report against the entries for that image | A failed check no entry covers, an entry whose control now passes (so a fixed audit retires its false positives), an entry past its review date, and, for an entry with `findings`, anything the audit found beyond what it accepts. It notes, without failing, controls the audit has no check for and `manual` entries whose check the audit does not title Manual. |

`just validate` warns 30 days before a review is due. `just exceptions` lists the registry, soonest review first, and `EXCEPTIONS_TODAY=<date> just exceptions` shows what will be due by a date. To review an entry, decide again, then set `decided_on` to the day and a new `review_by`. To end one, set `status: retired` with `retired_on` and `retired_reason` rather than delete it, so the decision stays on record.

The audit content is pinned to the last commit before the role release, not the head of its branch. The lockdown team updates the audit first and releases the role afterwards, so the head of the branch often expects variables the released role does not pass yet, and goss then fails before it runs a check. `just pin-audit <image>` sets the matching commit, and `just deps` refuses a newer one.

## Using an image

A VM built from an image is a first boot for cloud-init, so give it a NoCloud seed (or your platform's datasource) with at least one user and an SSH key. [`scripts/test.sh`](./scripts/test.sh) is a worked example. Some things work differently from a stock install:

| What | Why |
|---|---|
| `sudo` asks for a password, so give your user one (`passwd`, with `lock_passwd: false`) in the seed. | CIS requires a password for privilege escalation. A `NOPASSWD` rule in your seed still works, but takes the VM out of line with that control. |
| On `ubuntu-24.04`, outbound traffic is denied except DNS, HTTP, HTTPS and NTP, and inbound except SSH. On `rhel-9`, firewalld's default zone allows SSH and DHCPv6 replies only. | The CIS firewall controls, with each role's defaults. Open more with `ufw` or `firewall-cmd` at deployment. |
| `/tmp`, `/var/tmp`, `/var/log` and `/var/log/audit` are `noexec`, and each of those plus `/home` and `/var` is its own LVM volume. | CIS 1.1.2. The volume group has free space: grow a volume with `lvextend --resizefs`. |
| Only the filesystem modules the image needs can load: see each image's README. Containers need `overlay`, for example. | CIS asks for unused filesystem modules to be blocked. To allow one, remove its lines from `/etc/modprobe.d/image-unused-filesystems.conf`, or build an image on this one that keeps it, with its own exception. |
| AIDE makes its database on the VM's first boot, after cloud-init, at idle priority. It takes a few minutes. | The image's database describes the build VM, so AIDE would report every change deployment made. |
| There is no swap. | Add it at deployment if the workload needs it. |

## Quick start

You need [uv](https://docs.astral.sh/uv/), [just](https://github.com/casey/just), git, gpg, QEMU with KVM, the `ovmf` UEFI firmware and `xorriso`. On Ubuntu or Debian:

```bash
sudo apt-get install qemu-system-x86 qemu-utils ovmf xorriso
sudo usermod -aG kvm "$USER"   # then log in again
```

Build and test an image:

```bash
just all ubuntu-24.04
```

With KVM, a build takes 8 to 15 minutes and the test a few more on a 32 core machine. The first build also downloads the ISO (about 3 GB) into `.cache/packer`.

## Recipes

| Recipe | What it does |
|---|---|
| `just images` | Lists the images. |
| `just targets <image>` | Lists an image's targets, which are its Packer source types. |
| `just tools` | Installs the pinned Packer into `.tools`, after checking HashiCorp's signature on the release checksums and the archive's SHA-256. |
| `just deps` | Installs the locked Python tools and the pinned collections, and fetches every image's lockdown role (refusing a tag that has moved) and audit content. |
| `just lint` | yamllint, ansible-lint on the production profile, shellcheck, `packer fmt -check` and zizmor. |
| `just validate` | Checks every image definition, hardening profile and exception, then runs `packer validate` for each image and target. |
| `just build <image> [target]` | Builds into `output/<image>/<target>`. The target defaults to `qemu`. |
| `just test <image> [target]` | Boots the built image as a new VM, checks it, audits it and runs the gate. With `KEEP=1` it leaves the VM running and prints how to connect. |
| `just all <image> [target]` | Build, then test. |
| `just gate <image> [target]` | Re-runs the gate on the last audit report, for example after editing `exceptions.yml`. |
| `just exceptions` | Lists the exception registry, soonest review first. |
| `just docs` | Writes each image's README from its `image.yml`, `hardening/` and the exception registry. |
| `just pin-audit [image...]` | Pins each image's audit content to the commit that matches its role release. Run it after a role bump. |
| `just secrets` | Scans the full git history with gitleaks. |
| `just clean [image]` | Deletes build output. |

CI runs these same recipes: [`ci.yml`](./.github/workflows/ci.yml) lints and validates every change, and each image's own workflow calls [`image.yml`](./.github/workflows/image.yml) to build, test and gate it on a GitHub-hosted runner with KVM. An image's workflow runs when anything it is built from changes, every Sunday for security updates, and by hand.

## Layout

```text
images/<image>/
  image.yml            pinned ISO, lockdown role and audit content
  plugins.pkr.hcl      Packer and plugin versions
  variables.pkr.hcl    inputs, all rendered by scripts/images.py
  locals.pkr.hcl       shared Ansible settings and the per-build password
  qemu.pkr.hcl         the QEMU source; one file per target
  build.pkr.hcl        the steps, the same for every target
  autoinstall/         Ubuntu installer answers for the ISO targets
  kickstart/           Red Hat family installer answers for the ISO targets
  hardening/           common.yml and one file per target
  README.md            written by `just docs`
exceptions.yml         the CIS exception registry
docs/                  longer notes and plans, such as building rhel-9 from RHEL
ansible/               base, harden, generalise and verify playbooks
scripts/               images.py (pins, rendering, validation, gate), build, test and validate scripts
keys/                  HashiCorp's release signing key, which `just tools` checks Packer with
versions.yml           pinned tools
requirements.yml       pinned Ansible collections
```

## Pins and updates

Every third-party input is pinned, and [`SECURITY.md`](./SECURITY.md) lists how each one is checked. Renovate opens a pull request for new lockdown role releases (one per image, so that image's pipeline builds, tests and audits the change before it merges; run `just pin-audit <image>` on its branch to move the audit content to match), Packer and its plugins, the Ansible collections, the Python tools and GitHub Actions digests. Installer ISOs are bumped by hand: see [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). Report security problems as [`SECURITY.md`](./SECURITY.md) describes.

## Licence

[MIT](./LICENSE).

<!-- Written by `just docs` from image.yml, ../../tools/tools.yml and ../../exceptions.yml. Edit those, not this file. -->

# azdo-agent-ubuntu-24.04

Azure DevOps scale set agent, on the hardened ubuntu-24.04 image.

Azure DevOps installs the Azure Pipelines agent itself when it adds a VM to a scale set pool, as Microsoft advises, so the image does not. It has the libraries the agent needs and the tools pipelines use. Podman, with the docker command, comes from the base image.

## Built from

The finished [`ubuntu-24.04`](../ubuntu-24.04) image, so it keeps that image's hardening: UBUNTU24-CIS `1.8.0`, CIS profile `level1-server`, audited with UBUNTU24-CIS-Audit at commit `4eb9eb9e6d39`. The build boots it as a new VM, patches it, adds the tools below and generalises it again. It does not harden it a second time: the test audits the result with the same gate, so a tool that weakens the hardening fails the build.

## Tools

From the catalogue in [`tools/tools.yml`](../../tools/tools.yml). Installed after the base image's hardening, as root, readable by every user. The test runs each one as an unprivileged user.

| Tool | Version | Installed from | What |
|---|---|---|---|
| `azure-pipelines-agent-deps` | the distribution's | the base image's signed packages, patched at every build | Libraries the Azure Pipelines agent needs (ICU, Kerberos, zlib) |
| `git` | the distribution's | the base image's signed packages, patched at every build | Git |
| `jq` | the distribution's | the base image's signed packages, patched at every build | jq |
| `python` | the distribution's | the base image's signed packages, patched at every build | Python 3.12, the base image's own |
| `uv` | `0.13.7` | release archive, SHA-256 pinned | uv, the Python package and project manager |
| `azure-cli` | `2.92.0` | own Python environment, hash-locked requirements | Azure CLI |
| `ansible` | `14.6.0` | own Python environment, hash-locked requirements | Ansible, with the community collections |
| `tenv` | `4.15.1` | release archive, SHA-256 pinned | tenv, the Terraform and OpenTofu version manager |
| `terraform` | `1.17.1` | through tenv, HashiCorp's signature checked | Terraform, the default version for tenv |
| `podman` | the distribution's | the base image's signed packages, patched at every build | Podman, with the docker command |
| `podman-compose` | `1.6.0` | own Python environment, hash-locked requirements | podman-compose, for Compose files, also as `docker compose` |

## Exceptions

The CIS controls this image does not meet, from the registry in [`exceptions.yml`](../../exceptions.yml). They include every exception for its base, `ubuntu-24.04`. The test fails the build on any other audit failure, on an exception whose control now passes, and on one past its review date.

| ID | Controls | Kind | Risk | Review by | Decision |
|---|---|---|---|---|---|
| EX-001 | 1.4.1 | deviation | low | 2027-05-11 | **No bootloader password in the image.** A bootloader password set in the image would be the same on every VM built from it, so anyone with the image would know it, and it would block the console recovery that cloud platforms and hypervisors rely on. Mitigation: Changing boot entries needs access to the VM's console, which the platform's own access control protects. Set a password per VM at deployment where policy needs one. |
| EX-002 | 1.1.1.10 | deviation | low | 2027-05-13 | **Filesystem kernel modules the image needs stay loadable.** The image needs fat, which vfat uses, to mount the EFI system partition at every boot, isofs to read cloud-init seed disks (NoCloud and config drives), and overlay for podman's overlay storage driver, which every container uses. RHEL 9 also keeps jbd2, which ext4 needs, because CIS counts ext4 as a standard filesystem and RHEL builds both as modules. The harden step blocks every other filesystem module the kernel ships, apart from those mounted and the ones CIS counts as standard (ext2, ext3, ext4, xfs and vfat), because the lockdown roles only report on this control. The audit fails while any unused module can load, so it cannot pass in full. Podman is in the golden images because containers are the basis of most builds; its vfs driver needs no module but copies every layer in full, which is too slow and too large for CI. Mitigation: fat is mounted on every boot anyway, and isofs only parses discs attached to the VM, which the platform controls. overlay is the filesystem the container engines use everywhere, and is loaded only when a container starts. Images built on this one that need another module record their own exception. |
| EX-003 | 1.2.1.2 | manual | low | 2027-05-11 | **Package repositories (manual control).** The image uses only its distribution's own signed repositories, as the installer configured them. Review any repository a deployment adds. |
| EX-004 | 2.1.22 | manual | low | 2027-05-11 | **Listening services (manual control).** The image listens on SSH (22/tcp) only, apart from local services on loopback (chronyd's command port on rhel-9) and, on ubuntu-24.04, the DHCP client. Review services a deployment adds. |
| EX-005 | 4.2.5 | manual | low | 2027-05-11 | **Outbound firewall policy (manual control).** The firewall denies outbound traffic except DNS, HTTP, HTTPS and NTP, the lockdown role's default port list. Review it against your policy. |
| EX-006 | 4.2.6 | manual | low | 2027-05-11 | **Firewall rules for open ports (manual control).** SSH is the only port open to the network, and the firewall allows it. Review ports a deployment opens. |
| EX-007 | 6.1.1.2 | manual | low | 2027-05-11 | **Journal file permissions (manual control).** The image keeps systemd's default journal file permissions. Review them against your policy. |
| EX-018 | 1.3.1.3 | deviation | low | 2027-05-13 | **AppArmor profiles stay as Ubuntu ships them, so containers run.** Running containers is a main use case for these images, and this control stops it. UBUNTU24-CIS applies it by moving every AppArmor profile into complain mode, including the ones Ubuntu ships with flags=(unconfined), which only name a program and allow it user namespaces. Tested on 13 November 2026: with podman's profile in complain mode the kernel refuses overlayfs its whiteouts and tmpfiles, so podman has no storage driver, as root or not, and with crun's no container starts. Neither logs a denial. So the image does not apply the control, and the audit skips it. Mitigation: AppArmor stays enabled and as Ubuntu ships it, checked on the image on 13 November 2026: nine profiles in enforce mode, among them chronyd, unix-chkpwd and unprivileged_userns, where the control at Level 1 left one; four in complain mode; and the ones Ubuntu ships unconfined stay unconfined. Ubuntu's restriction on unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns) stays on. Podman confines each container itself: a rootful container runs under podman's own enforcing AppArmor profile with a seccomp filter, and a rootless one, which is how CI agents run, with a seccomp filter in a user namespace that maps root in the container to the user's subordinate IDs. |

## Targets

| Target | Packer source |
|---|---|
| `qemu` | [`qemu.pkr.hcl`](./qemu.pkr.hcl) |

Build its base first, then build and test it: `just build ubuntu-24.04`, then `just all azdo-agent-ubuntu-24.04`.

<!-- Written by `just docs` from image.yml, hardening/ and ../../exceptions.yml. Edit those, not this file. -->

# ubuntu-24.04

Ubuntu 24.04 LTS Server (minimal), hardened to CIS Level 1 Server.

## Built from

Pinned in [`image.yml`](./image.yml).

| Input | Version | Pinned to |
|---|---|---|
| Installer ISO | `ubuntu-24.04.5-live-server-amd64.iso` | SHA-256 `97f3d7ffb032c3eb...` |
| Hardening role | [UBUNTU24-CIS](https://github.com/ansible-lockdown/UBUNTU24-CIS) `1.8.0` | commit `3a2f05b9a804` |
| Audit content | [UBUNTU24-CIS-Audit](https://github.com/ansible-lockdown/UBUNTU24-CIS-Audit) `benchmark_v1.0.0` | commit `4eb9eb9e6d39` |

CIS profile: `level1-server`.

## Changes to the role's defaults

From [`hardening/common.yml`](./hardening/common.yml) and each target's file. Everything not listed runs as the role's defaults.

| Variable | Value | Targets | Reason |
|---|---|---|---|
| `ubtu24cis_level_2` | `false` | all | The role uses this for the audit only. The image applies Level 1 Server, so the audit checks Level 1 Server. |
| `ubtu24cis_rule_1_3_1_3` | `false` | all | Switched off: EX-018, AppArmor profiles stay as Ubuntu ships them, so containers run. |
| `ubtu24cis_ufw_allow_out_ports` | `[{"port": 53, "proto": "tcp"}, {"port": 53, "proto": "udp"}, {"port": 80, "proto": "tcp"}, {"port": 123, "proto": "udp"}, {"port": 443, "proto": "tcp"}, {"port": 22, "proto": "tcp"}]` | all | The role's list, with SSH (22/tcp) added, so git can reach Azure Repos and GitHub over SSH and Ansible can manage other hosts: a build agent's main jobs, and common on any server. The firewall still denies every other port out. RHEL 9's firewall does not filter outbound traffic at all. |

The harden step also blocks every filesystem kernel module the kernel ships, except those mounted, the ones CIS counts as standard (ext2, ext3, ext4, xfs and vfat), and the ones this image keeps: `fat`, `isofs` and `overlay` (targets: all; exception EX-002).

## Tools

From the catalogue in [`tools/tools.yml`](../../tools/tools.yml). Installed before the harden step, so the lockdown role hardens them with the rest of the system. The test runs each one as an unprivileged user.

| Tool | Version | Installed from | What |
|---|---|---|---|
| `podman` | the distribution's | the base image's signed packages, patched at every build | Podman, with the docker command |

## Exceptions

The CIS controls this image does not meet, from the registry in [`exceptions.yml`](../../exceptions.yml). The test fails the build on any other audit failure, on an exception whose control now passes, and on one past its review date.

| ID | Controls | Kind | Risk | Review by | Decision |
|---|---|---|---|---|---|
| EX-001 | 1.4.1 | deviation | low | 2027-05-11 | **No bootloader password in the image.** A bootloader password set in the image would be the same on every VM built from it, so anyone with the image would know it, and it would block the console recovery that cloud platforms and hypervisors rely on. Mitigation: Changing boot entries needs access to the VM's console, which the platform's own access control protects. Set a password per VM at deployment where policy needs one. |
| EX-002 | 1.1.1.10 | deviation | low | 2027-05-13 | **Filesystem kernel modules the image needs stay loadable.** The image needs fat, which vfat uses, to mount the EFI system partition at every boot, isofs to read cloud-init seed disks (NoCloud and config drives), and overlay for podman's overlay storage driver, which every container uses. RHEL 9 also keeps jbd2, which ext4 needs, because CIS counts ext4 as a standard filesystem and RHEL builds both as modules. The harden step blocks every other filesystem module the kernel ships, apart from those mounted and the ones CIS counts as standard (ext2, ext3, ext4, xfs and vfat), because the lockdown roles only report on this control. The audit fails while any unused module can load, so it cannot pass in full. Podman is in the golden images because containers are the basis of most builds; its vfs driver needs no module but copies every layer in full, which is too slow and too large for CI. Mitigation: fat is mounted on every boot anyway, and isofs only parses discs attached to the VM, which the platform controls. overlay is the filesystem the container engines use everywhere, and is loaded only when a container starts. Images built on this one that need another module record their own exception. |
| EX-003 | 1.2.1.2 | manual | low | 2027-05-11 | **Package repositories (manual control).** The image uses only its distribution's own signed repositories, as the installer configured them. Review any repository a deployment adds. |
| EX-004 | 2.1.22 | manual | low | 2027-05-11 | **Listening services (manual control).** The image listens on SSH (22/tcp) only, apart from local services on loopback (chronyd's command port on rhel-9) and, on ubuntu-24.04, the DHCP client. Review services a deployment adds. |
| EX-005 | 4.2.5 | manual | low | 2027-05-11 | **Outbound firewall policy (manual control).** The firewall denies outbound traffic except DNS, HTTP, HTTPS and NTP, the lockdown role's default port list, and SSH, which the image adds so git and Ansible can work over SSH. Review it against your policy. |
| EX-006 | 4.2.6 | manual | low | 2027-05-11 | **Firewall rules for open ports (manual control).** SSH is the only port open to the network, and the firewall allows it. Review ports a deployment opens. |
| EX-007 | 6.1.1.2 | manual | low | 2027-05-11 | **Journal file permissions (manual control).** The image keeps systemd's default journal file permissions. Review them against your policy. |
| EX-018 | 1.3.1.3 | deviation | low | 2027-05-13 | **AppArmor profiles stay as Ubuntu ships them, so containers run.** Running containers is a main use case for these images, and this control stops it. UBUNTU24-CIS applies it by moving every AppArmor profile into complain mode, including the ones Ubuntu ships with flags=(unconfined), which only name a program and allow it user namespaces. Tested on 13 November 2026: with podman's profile in complain mode the kernel refuses overlayfs its whiteouts and tmpfiles, so podman has no storage driver, as root or not, and with crun's no container starts. Neither logs a denial. So the image does not apply the control, and the audit skips it. Mitigation: AppArmor stays enabled and as Ubuntu ships it, checked on the image on 13 November 2026: nine profiles in enforce mode, among them chronyd, unix-chkpwd and unprivileged_userns, where the control at Level 1 left one; four in complain mode; and the ones Ubuntu ships unconfined stay unconfined. Ubuntu's restriction on unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns) stays on. Podman confines each container itself: a rootful container runs under podman's own enforcing AppArmor profile with a seccomp filter, and a rootless one, which is how CI agents run, with a seccomp filter in a user namespace that maps root in the container to the user's subordinate IDs. |

## Targets

| Target | Packer source | Hardening file |
|---|---|---|
| `qemu` | [`qemu.pkr.hcl`](./qemu.pkr.hcl) | [`hardening/qemu.yml`](./hardening/qemu.yml) |

Build and test it with `just all ubuntu-24.04 <target>`.

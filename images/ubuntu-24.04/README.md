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

The harden step also blocks every filesystem kernel module the kernel ships, except those mounted, the ones CIS counts as standard (ext2, ext3, ext4, xfs and vfat), and the ones this image keeps: `fat` and `isofs` (targets: all; exception EX-002).

## Exceptions

The CIS controls this image does not meet, from the registry in [`exceptions.yml`](../../exceptions.yml). The test fails the build on any other audit failure, on an exception whose control now passes, and on one past its review date.

| ID | Controls | Kind | Risk | Review by | Decision |
|---|---|---|---|---|---|
| EX-001 | 1.4.1 | deviation | low | 2027-05-11 | **No bootloader password in the image.** A bootloader password set in the image would be the same on every VM built from it, so anyone with the image would know it, and it would block the console recovery that cloud platforms and hypervisors rely on. Mitigation: Changing boot entries needs access to the VM's console, which the platform's own access control protects. Set a password per VM at deployment where policy needs one. |
| EX-002 | 1.1.1.10 | deviation | low | 2027-05-11 | **Filesystem kernel modules the image needs stay loadable.** The image needs fat, which vfat uses, to mount the EFI system partition at every boot, and isofs to read cloud-init seed disks (NoCloud and config drives). RHEL 9 also keeps jbd2, which ext4 needs, because CIS counts ext4 as a standard filesystem and RHEL builds both as modules. The harden step blocks every other filesystem module the kernel ships, apart from those mounted and the ones CIS counts as standard (ext2, ext3, ext4, xfs and vfat), because the lockdown roles only report on this control. The audit fails while any unused module can load, so it cannot pass in full. Mitigation: fat is mounted on every boot anyway, and isofs only parses discs attached to the VM, which the platform controls. Images built on this one that need another module, such as overlay for containers, record their own exception. |
| EX-003 | 1.2.1.2 | manual | low | 2027-05-11 | **Package repositories (manual control).** The image uses only its distribution's own signed repositories, as the installer configured them. Review any repository a deployment adds. |
| EX-004 | 2.1.22 | manual | low | 2027-05-11 | **Listening services (manual control).** The image listens on SSH (22/tcp) only, apart from local services on loopback (chronyd's command port on rhel-9) and, on ubuntu-24.04, the DHCP client. Review services a deployment adds. |
| EX-005 | 4.2.5 | manual | low | 2027-05-11 | **Outbound firewall policy (manual control).** The firewall denies outbound traffic except DNS, HTTP, HTTPS and NTP, the lockdown role's default port list. Review it against your policy. |
| EX-006 | 4.2.6 | manual | low | 2027-05-11 | **Firewall rules for open ports (manual control).** SSH is the only port open to the network, and the firewall allows it. Review ports a deployment opens. |
| EX-007 | 6.1.1.2 | manual | low | 2027-05-11 | **Journal file permissions (manual control).** The image keeps systemd's default journal file permissions. Review them against your policy. |

## Targets

| Target | Packer source | Hardening file |
|---|---|---|
| `qemu` | [`qemu.pkr.hcl`](./qemu.pkr.hcl) | [`hardening/qemu.yml`](./hardening/qemu.yml) |

Build and test it with `just all ubuntu-24.04 <target>`.

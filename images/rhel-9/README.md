<!-- Written by `just docs` from image.yml, hardening/ and ../../exceptions.yml. Edit those, not this file. -->

# rhel-9

Red Hat Enterprise Linux 9 family (minimal), hardened to CIS Level 1 Server.

The QEMU target installs AlmaLinux 9, which is built from the same sources as RHEL 9 and which the RHEL9-CIS role supports, because the RHEL ISO needs a Red Hat login and a subscription to patch. The cloud targets, when they come, will start from Red Hat's own pay-as-you-go images. The work to install from RHEL itself is in docs/rhel.md.

## Built from

Pinned in [`image.yml`](./image.yml).

| Input | Version | Pinned to |
|---|---|---|
| Installer ISO | `AlmaLinux-9.8-x86_64-minimal.iso` | SHA-256 `7762a4b45a662357...` |
| Hardening role | [RHEL9-CIS](https://github.com/ansible-lockdown/RHEL9-CIS) `2.4.2` | commit `a3ee6a3bb780` |
| Audit content | [RHEL9-CIS-Audit](https://github.com/ansible-lockdown/RHEL9-CIS-Audit) `benchmark_v2.0.0` | commit `82a1ab34d5e1` |

CIS profile: `level1-server`.

## Changes to the role's defaults

From [`hardening/common.yml`](./hardening/common.yml) and each target's file. Everything not listed runs as the role's defaults.

| Variable | Value | Targets | Reason |
|---|---|---|---|
| `rhel9cis_authselect_custom_profile_name` | `"cis"` | all | The role refuses to run with its example name. The name only labels the custom authselect profile the role creates and selects, under /etc/authselect/custom. |
| `rhel9cis_disruption_high` | `true` | all | The role skips the PAM, password policy and account controls (5.3.2 to 5.3.3, 5.4.2.1, 5.4.2.2, 5.4.2.7, 5.4.2.8 and 7.2.9) unless this is set, because they can lock users out of a running system. The role's own notes say they are safe on a new build with nothing configured yet, which is what an image build is. |
| `rhel9cis_ipv6_disable_method` | `""` | all | IPv6 stays enabled (the role's default rhel9cis_ipv6_required), so there is no method of disabling it. Left at sysctl, the audit checks that IPv6 is disabled by sysctl even though the image requires it. |
| `rhel9cis_level_2` | `false` | all | The role uses this for the audit only. The image applies Level 1 Server, so the audit checks Level 1 Server. |
| `rhel9cis_rule_6_2_2_1_2` | `false` | all | Exception EX-008. |
| `rhel9cis_rule_6_2_2_1_3` | `false` | all | Exception EX-008. |
| `rhel9cis_sshd_allowusers` | `""` | all | The role's default allows SSH for the connecting user only, which is the build account, and the build deletes it, so no one could log in to a VM. SSH access stays limited by the role's default DenyUsers, which CIS 5.1.7 accepts. Restrict it further at deployment. |

The harden step also blocks every filesystem kernel module the kernel ships, except those mounted, the ones CIS counts as standard (ext2, ext3, ext4, xfs and vfat), and the ones this image keeps: `fat`, `isofs` and `jbd2` (targets: all; exception EX-002).

The harden step also sets the default firewall zone to allow only `ssh`, `dhcpv6-client` (targets: all).

## Exceptions

The CIS controls this image does not meet, from the registry in [`exceptions.yml`](../../exceptions.yml). The test fails the build on any other audit failure, on an exception whose control now passes, and on one past its review date.

| ID | Controls | Kind | Risk | Review by | Decision |
|---|---|---|---|---|---|
| EX-001 | 1.4.1 | deviation | low | 2027-05-11 | **No bootloader password in the image.** A bootloader password set in the image would be the same on every VM built from it, so anyone with the image would know it, and it would block the console recovery that cloud platforms and hypervisors rely on. Mitigation: Changing boot entries needs access to the VM's console, which the platform's own access control protects. Set a password per VM at deployment where policy needs one. |
| EX-002 | 1.1.1.9 | deviation | low | 2027-05-11 | **Filesystem kernel modules the image needs stay loadable.** The image needs fat, which vfat uses, to mount the EFI system partition at every boot, and isofs to read cloud-init seed disks (NoCloud and config drives). RHEL 9 also keeps jbd2, which ext4 needs, because CIS counts ext4 as a standard filesystem and RHEL builds both as modules. The harden step blocks every other filesystem module the kernel ships, apart from those mounted and the ones CIS counts as standard (ext2, ext3, ext4, xfs and vfat), because the lockdown roles only report on this control. The audit fails while any unused module can load, so it cannot pass in full. Mitigation: fat is mounted on every boot anyway, and isofs only parses discs attached to the VM, which the platform controls. Images built on this one that need another module, such as overlay for containers, record their own exception. |
| EX-004 | 2.1.22 | manual | low | 2027-05-11 | **Listening services (manual control).** The image listens on SSH (22/tcp) only, apart from local services on loopback (chronyd's command port on rhel-9) and, on ubuntu-24.04, the DHCP client. Review services a deployment adds. |
| EX-008 | 6.2.2.1.2, 6.2.2.1.3 | deviation | medium | 2027-05-11 | **No remote journal destination in the image.** Where a VM's logs go, and the certificates that authenticate it to the log server, belong to each deployment, not to an image. RHEL9-CIS would otherwise point systemd-journal-upload at its example address, 192.168.50.42, with certificates that do not exist, and enable it. The image installs systemd-journal-remote (6.2.2.1.1) and keeps the receiver masked (6.2.2.1.4). UBUNTU24-CIS skips these controls itself when no log server is set, so ubuntu-24.04 needs no exception. Mitigation: Logs stay on the VM, in the persistent journal, until a deployment sends them on: set URL and the certificate paths in /etc/systemd/journal-upload.conf and enable systemd-journal-upload, or use the platform's own log agent. |
| EX-009 | 4.2.1 | manual | low | 2027-05-11 | **Firewall services (manual control).** The default zone allows only the ssh and dhcpv6-client services and no ports. The harden step sets that from firewall_services in the image's hardening/common.yml, removing the cockpit service AlmaLinux allows by default. Review services and ports a deployment opens. |
| EX-010 | 4.2.2 | manual | low | 2027-05-11 | **Firewall loopback traffic (manual control).** firewalld accepts traffic on the loopback interface, and the role adds rules to the default zone that drop traffic from 127.0.0.1 or ::1 arriving on any other interface. |
| EX-011 | 7.1.13 | manual | low | 2027-05-11 | **SUID and SGID files (manual control).** Every SUID and SGID file in the image belongs to a distribution package and is unmodified (rpm -V): mount, umount, su, sudo, passwd, chage, gpasswd, newgrp, write, crontab, pam_timestamp_check, unix_chkpwd, grub2-set-bootflag, utempter and ssh-keysign. Review files a deployment adds. |
| EX-012 | 5.4.2.4 | false-positive | low | 2027-05-11 | **Locked root account fails the root access check.** Root's password is locked, so root can only be reached through sudo. RHEL9-CIS's own check for this control accepts a locked password, and so does UBUNTU24-CIS-Audit for the same control, but this audit check only accepts a set password. A root password in the image would be the same on every VM. |
| EX-013 | 5.1.7 | false-positive | low | 2027-05-11 | **SSH access check cannot match sshd syntax.** sshd's effective configuration (sshd -T) has DenyUsers nobody, the role's default, which limits SSH access as the control asks. The audit check looks for lines such as "DenyUsers: nobody", with a colon sshd's syntax never has, and wants all four of AllowUsers, AllowGroups, DenyUsers and DenyGroups, so it cannot pass. |
| EX-014 | 3.1.2 | false-positive | low | 2027-05-11 | **No wireless hardware fails the wireless check.** The image has no wireless interfaces (nothing under /sys/class/net/*/wireless), so the role rightly changes nothing. The audit check reads NetworkManager's radio switches instead, which stay on with no hardware behind them. |
| EX-015 | 7.1.12 | false-positive | low | 2027-05-11 | **Unowned files check lists every file.** The audit check runs find with the role's list of excluded paths but no -nouser or -nogroup test, so it lists every file on every local filesystem. Run with those tests, the same search finds no unowned files outside the paths the role excludes. |
| EX-016 | 1.7.2, 1.7.5 | false-positive | low | 2027-05-11 | **Login banner check expects a trailing space.** /etc/issue holds the role's banner with no operating system details and is owned by root with mode 0644. The audit check expects the banner followed by a space the role does not write. 1.7.5 is listed because the same check carries both control numbers. |
| EX-017 | 5.4.1.2 | false-positive | low | 2027-05-11 | **Level 2 minimum password age checked at Level 1.** Both lockdown roles tag this control Level 2, so the Level 1 Server profile does not apply it and PASS_MIN_DAYS stays 0. RHEL9-CIS-Audit checks it at Level 1. Mitigation: Set PASS_MIN_DAYS at deployment where policy applies Level 2. |

## Targets

| Target | Packer source | Hardening file |
|---|---|---|
| `qemu` | [`qemu.pkr.hcl`](./qemu.pkr.hcl) | [`hardening/qemu.yml`](./hardening/qemu.yml) |

Build and test it with `just all rhel-9 <target>`.

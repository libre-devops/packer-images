<!-- Written by `just docs` from image.yml, ../../tools/tools.yml and ../../exceptions.yml. Edit those, not this file. -->

# azdo-agent-rhel-9

Azure DevOps scale set agent, on the hardened rhel-9 image.

Azure DevOps installs the Azure Pipelines agent itself when it adds a VM to a scale set pool, as Microsoft advises, so the image does not. It has the libraries the agent needs and the tools pipelines use. The shared tool cache at /opt/hostedtoolcache is writable by the AzDevOps account that Azure DevOps makes, and by no one else. Podman, with the docker command, comes from the base image. Its QEMU target builds on AlmaLinux 9, as rhel-9's does.

## Built from

The finished [`rhel-9`](../rhel-9) image, so it keeps that image's hardening: RHEL9-CIS `2.4.2`, CIS profile `level1-server`, audited with RHEL9-CIS-Audit at commit `82a1ab34d5e1`. The build boots it as a new VM, patches it, adds the tools below and generalises it again. It does not harden it a second time: the test audits the result with the same gate, so a tool that weakens the hardening fails the build.

## Tools

From the catalogue in [`tools/tools.yml`](../../tools/tools.yml). Installed after the base image's hardening, as root, readable by every user. The test runs each one as an unprivileged user.

| Tool | Version | Installed from | What |
|---|---|---|---|
| `runner-libraries` | the distribution's | the base image's signed packages, patched at every build | Libraries the Azure Pipelines agent and the GitHub Actions runner need (ICU, Kerberos, zlib) |
| `acl` | the distribution's | the base image's signed packages, patched at every build | POSIX ACL tools (setfacl, getfacl) |
| `hosted-toolcache` | none | a directory the image makes, owned by root and a group | Shared tool cache at /opt/hostedtoolcache, writable by the toolcache group only |
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

The CIS controls this image does not meet, from the registry in [`exceptions.yml`](../../exceptions.yml). They include every exception for its base, `rhel-9`. The test fails the build on any other audit failure, on an exception whose control now passes, and on one past its review date.

| ID | Controls | Kind | Risk | Review by | Decision |
|---|---|---|---|---|---|
| EX-001 | 1.4.1 | deviation | low | 2027-05-11 | **No bootloader password in the image.** A bootloader password set in the image would be the same on every VM built from it, so anyone with the image would know it, and it would block the console recovery that cloud platforms and hypervisors rely on. Mitigation: Changing boot entries needs access to the VM's console, which the platform's own access control protects. Set a password per VM at deployment where policy needs one. |
| EX-002 | 1.1.1.9 | deviation | low | 2027-05-13 | **Filesystem kernel modules the image needs stay loadable.** The image needs fat, which vfat uses, to mount the EFI system partition at every boot, isofs to read cloud-init seed disks (NoCloud and config drives), and overlay for podman's overlay storage driver, which every container uses. RHEL 9 also keeps jbd2, which ext4 needs, because CIS counts ext4 as a standard filesystem and RHEL builds both as modules. The harden step blocks every other filesystem module the kernel ships, apart from those mounted and the ones CIS counts as standard (ext2, ext3, ext4, xfs and vfat), because the lockdown roles only report on this control. The audit fails while any unused module can load, so it cannot pass in full. Podman is in the golden images because containers are the basis of most builds; its vfs driver needs no module but copies every layer in full, which is too slow and too large for CI. Mitigation: fat is mounted on every boot anyway, and isofs only parses discs attached to the VM, which the platform controls. overlay is the filesystem the container engines use everywhere, and is loaded only when a container starts. Images built on this one that need another module record their own exception. |
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

| Target | Packer source |
|---|---|
| `qemu` | [`qemu.pkr.hcl`](./qemu.pkr.hcl) |

Build its base first, then build and test it: `just build rhel-9`, then `just all azdo-agent-rhel-9`.

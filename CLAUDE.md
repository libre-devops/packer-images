# CLAUDE.md

Context for working in this repository. Read this before making changes.

## What this repo is

Golden VM images for Libre DevOps, built with Packer and configured with Ansible. Each image is installed from a pinned vendor ISO (or, later, a cloud marketplace image), patched, hardened with the matching ansible-lockdown CIS role, generalised, then booted as a new VM and audited before anything trusts it.

Built so far, for the `qemu` target: `ubuntu-24.04`, and `rhel-9` (RHEL9-CIS, installed from the AlmaLinux 9 minimal ISO, since the RHEL ISO needs a Red Hat login and a subscription to patch; `docs/rhel.md` is the plan for real RHEL). On those, the first role image: `azdo-agent-ubuntu-24.04`, for Azure DevOps scale set agents.

On 13 November 2026 Craig moved the Azure DevOps agent image ahead of Windows, and said the QEMU target only proves the code: the cloud images are the product. Next: the `azure-arm` target (Compute Gallery), with Terraform for the gallery and a build VM, then `amazon-ebs` (AMI). Then Windows Server 2025 (ansible-lockdown Windows-2025-CIS) and Windows 11 (Windows-11-CIS), and more role images such as AVD. Cloud builds cost money, so they wait until Craig says so.

## Hard constraints

**Ansible configures, Packer builds.** A template declares sources and runs the playbooks in `ansible/`: `base.yml`, `tools.yml`, `harden.yml` (golden images only) and `generalise.yml`. No shell provisioners, no inline scripts, no `-e` or `--skip-tags` in templates.

**Hardening is ansible-lockdown, on every OS.** Windows too: Craig asked to keep one toolchain, so HardeningKitty is not used. Never copy a lockdown role or its audit content into the repo. Pin it in `image.yml` to a tag and the commit it must resolve to.

**Role images build on golden images and never harden again.** A role image's `image.yml` names its `base` and lists `tools`, and has no ISO or hardening: it takes the base's role, audit content, profile and exceptions. It starts from the base's finished qcow2 with a cloud-init seed. The test audits it with the base's gate, so a tool that weakens the hardening fails the build; record a role image's own exception only for a failure its tools cause.

**Every tool an image installs comes from `tools/tools.yml`, pinned.** Distribution packages first, since the OS vendor signs and patches them. Otherwise a release archive with its SHA-256 (checked against the vendor's checksums by `just pin-tools`), a Python application from hash-locked wheels in its own `/opt` environment, or Terraform through tenv with the pinned HashiCorp key. No `curl | bash`, no `latest`, no vendor apt or dnf repository without a pinned key, no `chmod 777`, no `safe.directory '*'`, no `TENV_AUTO_INSTALL`. Golden images install their tools before the harden step. Run `just pin-tools` after any version change.

**Do not harden where it stops what the images are for.** Craig, 13 November 2026: where a CIS control most impacts functionality, skip it, document it and make it clear. Running containers is a main use case. Switch such a control off in the hardening profile with an exception that says what it breaks and how that was proven on a test VM, and add it to the README's "Hardening skipped so the images work" table. Never apply a control and then undo or work around it in a later step.

**Every deviation from a lockdown role's defaults is an entry in `hardening/*.yml` with a reason.** `just validate` checks each variable exists in the pinned role.

**Every CIS control an image does not meet is an entry in `exceptions.yml`**, the one registry, which Craig asked for on 11 November 2026: kind, risk, reason, mitigation, controls per image, who decided, when, and a review date at most a year out. `just validate` and the gate both check it (README, "Exceptions"). Group entries by subject across images rather than one per image. A setting that switches a rule off names its entry with `exception:`. Never weaken the checks to make a build pass; record the decision instead, and ask Craig when the decision is a real trade-off.

**Free first.** Only the QEMU target runs, locally and on GitHub's runners with KVM. Do not create cloud resources or add cloud credentials without Craig asking.

**This is a public Libre DevOps repo.** No work context: no corporate proxy or CA support, no employer names, hosts, domains or naming conventions, unless Craig asks.

**Every CI step is a just recipe**, and the recipes call scripts in `scripts/`. Keep logic out of the justfile.

**Writing:** British English, no em dashes or en dashes anywhere (docs, comments, commit messages). Commit as Craig, signed, no trailers of any kind. Do not commit or push until he says so.

## Things already learned the hard way

**just shebang recipes fail on this machine.** just writes them to `$XDG_RUNTIME_DIR`, which is mounted `noexec` on WSL (`/run/user/1000`), so they die with `Permission denied (os error 13)`. Put multi-line logic in `scripts/` instead.

**`packer validate` runs the Ansible provisioner's prepare step**, which needs `ansible-playbook` on PATH. Every script puts `.tools/bin` and `.venv/bin` first on PATH itself, so it works with or without just.

**Install tools into `.tools`, never `$RUNNER_TEMP`.** A directory added through `GITHUB_PATH` only reaches PATH in the next step, and `just build` installs and builds in one step.

**The lockdown role's `ubtu24cis_level_1` and `ubtu24cis_level_2` only feed the audit.** The remediation picks a profile by tag (`--tags level1-server`), so `hardening_tags` is passed separately and `harden.yml` includes the role with `tags: always`.

**Ubuntu 26.04 has no `sg` or `newgrp`.** After `usermod -aG kvm`, the current session cannot pick the group up without a new login. A `setfacl` entry on `/dev/kvm` does not last either: udev resets the device's permissions within minutes. `sudo -u "$USER" --preserve-env=PATH,HOME,XDG_RUNTIME_DIR just build ...` works, because sudo rebuilds the group list from `/etc/group`.

**The lockdown roles fetch goss from `github.com/krameff/goss`**, a fork, checksum-pinned in the role's `audit_bin_version`. That is the lockdown team's choice; note it in SECURITY.md rather than overriding it.

**The audit content has no releases**, only a branch per benchmark version (`benchmark_v1.0.0`), so it is pinned to a commit and copied in as a tarball (`audit_content: archive`). That also keeps `git` out of the image.

**The audit branch runs ahead of the role release.** The lockdown team updates the audit content first and releases the role afterwards. On 9 November 2026 the head of `UBUNTU24-CIS-Audit` (5 November) needed `ubtu24cis_tmp_svc`, which UBUNTU24-CIS 1.8.0 (22 October) does not pass to the audit, and goss failed before running a single check: `map has no entry for key "ubtu24cis_tmp_svc"`. The run script then only says "There were issues when running the audit". So the audit is pinned to the last commit before the role release: `just pin-audit` sets it, `just deps` refuses a newer one, and Renovate does not bump it on its own. After Renovate bumps a role, run `just pin-audit <image>` on its branch.

**Goss reports every CIS "Manual" control as failed.** Expect five or so on any Linux image. They are `kind: manual` entries in `exceptions.yml`, with a reason grounded in what the image actually does, checked on a test VM (`KEEP=1 just test <image>` leaves it running). Audit titles and role tags mark manual controls inconsistently (RHEL9-CIS 7.1.13 is neither), so the gate only notes a manual entry whose check is not titled Manual.

**Subiquity picks a country mirror by GeoIP** from wherever the build runs (`gb.archive.ubuntu.com` here). The autoinstall sets `apt.geoip: false` and the main archive, so the image is the same wherever it is built.

**`run_audit.sh` calls `dmidecode`** when `/sys/class/dmi/id/product_uuid` is missing, which it is under QEMU without `-uuid`. Minimal Ubuntu has no `dmidecode`, but it only feeds the report's metadata, so the error on stderr is harmless.

**AIDE is initialised during the build** by the lockdown roles, so its database describes the build VM. On 11 November 2026 Craig said he was happy with all the open decisions, including this one, so each VM re-initialises it on its first boot: `aide-first-boot.service` (`ConditionFirstBoot=yes`, after `cloud-final.service`, `WantedBy=cloud-init.target`). It is not `WantedBy=multi-user.target`: a target is ordered after the units it wants, and cloud-init's `cloud-final.service` can order itself after `multi-user.target`, which would make a loop. Proven on both images on 13 November 2026. The generalise play checks for the program the unit runs first (`aideinit` on Ubuntu, `aide` on RHEL), not for `aide` itself, which is `/usr/bin/aide` on Ubuntu and `/usr/sbin/aide` on RHEL: a check for `/usr/sbin/aide` skipped the unit on Ubuntu without a word, and only the test caught it. The test waits for the unit and fails if it did not run.

**RHEL 9 needs an x86-64-v2 CPU.** Packer's QEMU builder defaults to QEMU's own `qemu64` model, which is x86-64-v1, so the AlmaLinux installer kernel panics at once with `Fatal glibc error: CPU does not support x86-64-v2`, and Packer just waits for SSH until it times out. Every image sets `cpu_model = var.cpu_model`, default `host` (use `max` with `tcg`). When a build sits at "Waiting for SSH" with the disk not growing, look at the screen: Packer's VNC port is in the `qemu-system-x86_64 -vnc` argument.

**Anaconda reads `ks.cfg` from any disc labelled `OEMDRV`** without `inst.ks`, so the `rhel-9` boot command only picks "Install" from the ISO menu (`<up><enter>`) and no volume label is pinned. The AlmaLinux minimal ISO has no cloud-init or qemu-guest-agent, so `base.yml` installs them from the network repos. cloud-init stays off during the build (`/etc/cloud/cloud-init.disabled`), because with no datasource it could fall back and create a default user; the finalise script removes the marker after `cloud-init clean`.

**RHEL9-CIS checks two things before it runs that break a golden image.** It refuses to run while `rhel9cis_authselect_custom_profile_name` is its example name, and its default `rhel9cis_sshd_allowusers` is the connecting user, the build account the build deletes, which would lock everyone out of every VM. Both are set in `images/rhel-9/hardening/common.yml`. Look for the same in any new role: grep its defaults for `ansible_user`, `SUDO_USER` and `user_id`.

**The unused filesystem module control is checked by directory name.** The CIS script lists each directory under `/lib/modules/<kernel>/kernel/fs`, skips mounted types (from `findmnt -D`, so not pseudo filesystems) and ext2, ext3, ext4, xfs and vfat, and wants `blacklist <name>` plus `install <name> /bin/false` for the rest. For `overlayfs` it checks `overlay`. Some directory names are not module names (`nls`, `quota`, `smb`), so blocking them satisfies the audit without changing anything. `fat` must stay, because vfat needs it to mount the EFI partition, and on RHEL `jbd2`, which ext4 needs. goss prints the script's output with `\"` and `\n` escaped; the gate unescapes it before matching `findings.pattern`.

**Canonical's domains failed to resolve on the afternoon of 11 November 2026**: SERVFAIL from this machine's resolver (WSL, 10.255.255.254) and `Temporary failure resolving 'archive.ubuntu.com'` on GitHub's runners, while some public resolvers still answered. Subiquity then failed to fetch packages (apt exit 100, "An error occurred. Press enter to start a shell") and Packer sat waiting for SSH. QEMU's user networking uses the host's resolver. Check `getent hosts archive.ubuntu.com` before blaming the build.

**RHEL9-CIS skips its PAM and account controls unless `rhel9cis_disruption_high` is true** (5.3.2.x, 5.3.3.x, 5.4.2.1, 5.4.2.2, 5.4.2.7, 5.4.2.8, 7.2.9). The role's notes say that is safe on a clean build, so `rhel-9` sets it. Without it the image had no authselect profile at all, `nullok` in PAM and no faillock, and the audit failed 14 PAM checks. The role also points `systemd-journal-upload` at an example address (192.168.50.42) and enables it, which fails on every VM and would send logs to whoever holds that address; `rhel-9` switches 6.2.2.1.2 and 6.2.2.1.3 off under EX-008. UBUNTU24-CIS skips both itself when no log server is set.

**RHEL9-CIS-Audit (commit 82a1ab34d5e1) has checks that cannot pass or check the wrong thing**, recorded as `false-positive` entries EX-012 to EX-017: root locked (5.4.2.4), sshd access grep wants `DenyUsers: nobody` with a colon (5.1.7), wireless reads radio switches (3.1.2), unowned files has no `-nouser` test (7.1.12), banner wants a trailing space (1.7.2 with 1.7.5), and Level 2 minimum password age checked at Level 1 (5.4.1.2). It has no check for 1.1.1.9 at all. After a role or audit bump, the gate fails on any that a fixed audit now passes, which is the prompt to retire them. Read the check (`tar -xzOf .cache/audit/<name>.tar.gz ...`) before calling anything a false positive.

**AlmaLinux's default firewalld zone allows `cockpit`** although Cockpit is not installed. RHEL9-CIS only reports on 4.2.1, so `firewall_services` in the hardening profile sets the zone's services and the harden step applies it.

**The AlmaLinux minimal install has no `tar`**, which the audit needs to unpack its content (the role's unarchive fails with "Unable to find required 'gtar' or 'tar' binary"). `base.yml` installs it on the Red Hat family.

**UBUNTU24-CIS 1.3.1.3 runs `aa-complain /etc/apparmor.d/*`, which fails on any profile noble's AppArmor tools cannot parse.** passt's does not parse (`Operation {'runbindable'} cannot have a source`), and podman recommends passt. So the `package` method installs without recommends on Debian, and a catalogue entry lists what the tool needs (for podman: uidmap, slirp4netns, catatonit, dbus-user-session).

**AppArmor complain mode breaks podman on Ubuntu without logging a denial.** The role's 1.3.1.3 moves Ubuntu's `flags=(unconfined)` profiles to complain. Then the kernel refuses overlayfs its whiteouts and tmpfiles (`kernel does not support overlay fs ... permission denied when we tried to delete an item in the merged directory`, and `overlayfs: upper fs does not support tmpfile` in the kernel log), and crun says `Failed to re-execute libcrun via memory file descriptor`. Proven on 13 November 2026 by switching the two profiles on a `KEEP=1` test VM. So `ubuntu-24.04` does not apply 1.3.1.3 (`ubtu24cis_rule_1_3_1_3: false`, EX-018), and AppArmor stays as Ubuntu ships it.

**Podman caches its overlay self-test.** Root's result is in `/run/containers/storage/overlay/overlay-false`, a user's under their storage, and `podman system reset` cannot clear it while the driver is broken. Delete `/run/containers/storage` and `/var/lib/containers/storage` (or reset as the user) before retesting, or a fix looks as if it failed. The same temporary directory name in the error each time means a cached result.

**overlayfs refuses a lower layer that contains its upper one**, so `podman run --rootfs /:O` fails with `invalid argument` (the upper is under the user's home). The test's podman check overlays `/usr` instead.

**Stopping a Packer build:** send SIGINT to both Packer processes (the `packer build` wrapper and the `.tools/bin/packer` child); the wrapper alone keeps running. Never `pkill -f` with a pattern your own shell's command line contains.

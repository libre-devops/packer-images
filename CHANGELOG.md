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

### Changed

- Accepted audit failures moved from each image's `hardening/accepted.yml` into the registry, and the five decisions open on 9 November 2026 are recorded there or in the build: no bootloader password in the image (EX-001), only the filesystem modules the image needs stay loadable (EX-002), and AIDE re-initialises on first boot. Images stay unpublished for now.
- A setting that switches a CIS control off must name its exception, and one that switches off a whole section is refused.
- The test seed gives its user a sudo rule rather than an admin group, so it works on every family.
- The finalise script also removes the random seed and the DNF cache.

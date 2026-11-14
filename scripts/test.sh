#!/usr/bin/env bash
# Boots a built image as a new VM and checks it: first boot, generalisation,
# then the CIS audit and its gate. The image itself is never changed: the VM
# runs on a throwaway overlay disk.
#
# Usage: scripts/test.sh <image> [target]   (only the qemu target, for now)
#
# Set KEEP=1 to leave the VM running afterwards, pass or fail, with the SSH
# command printed, for looking around or debugging.
#
# Writes the audit report and summary to output/<image>/<target>/audit.

set -euo pipefail

image=${1:?usage: test.sh <image> [target]}
target=${2:-qemu}
[[ $target == qemu ]] || {
	echo "test.sh: only the qemu target can be booted locally" >&2
	exit 2
}

repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
# The pinned Packer (`just tools`) and the locked Python tools (`just deps`).
export PATH="$repo/.tools/bin:$repo/.venv/bin:$PATH"
out="$repo/output/$image/$target"
disk="$out/$image.qcow2"
images=(uv run --quiet --no-sync "$repo/scripts/images.py")
accelerator=${PKR_VAR_accelerator:-kvm}
firmware_code=${PKR_VAR_efi_firmware_code:-/usr/share/OVMF/OVMF_CODE_4M.fd}
firmware_vars=${PKR_VAR_efi_firmware_vars:-/usr/share/OVMF/OVMF_VARS_4M.fd}

[[ -f $disk ]] || {
	echo "test.sh: $disk does not exist: run just build $image $target first" >&2
	exit 1
}

workdir=$(mktemp -d)
qemu_pid=
password=
ssh_opts=()
cleanup() {
	if [[ ${KEEP:-0} == 1 && -n $qemu_pid ]]; then
		echo "KEEP=1: the VM is still running. Connect with:" >&2
		echo "  ssh ${ssh_opts[*]} tester@127.0.0.1" >&2
		echo "  sudo password: $password" >&2
		echo "Stop it with: kill $qemu_pid && rm -rf -- $workdir" >&2
		return
	fi
	if [[ -n $qemu_pid ]] && kill -0 "$qemu_pid" 2>/dev/null; then
		kill "$qemu_pid"
	fi
	rm -rf -- "$workdir"
}
trap cleanup EXIT

# A cloud-init seed, as any platform would give a new VM: a user with a key for
# SSH and a password for sudo, because the image allows no passwordless sudo.
# The sudo rule, not an admin group, so the same seed works on every family.
ssh-keygen -q -t ed25519 -N '' -C "packer-test-$image" -f "$workdir/test_key"
password=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
password_hash=$(openssl passwd -6 -stdin <<<"$password")
mkdir "$workdir/seed"
cat >"$workdir/seed/meta-data" <<META
instance-id: test-$(date +%s)
local-hostname: test-$image
META
cat >"$workdir/seed/user-data" <<USER
#cloud-config
users:
  - name: tester
    sudo: ['ALL=(ALL) ALL']
    shell: /bin/bash
    lock_passwd: false
    passwd: '$password_hash'
    ssh_authorized_keys:
      - $(cat "$workdir/test_key.pub")
ssh_pwauth: false
USER
xorriso -as mkisofs -quiet -volid cidata -joliet -rock -o "$workdir/seed.iso" "$workdir/seed/user-data" "$workdir/seed/meta-data"

qemu-img create -q -f qcow2 -b "$disk" -F qcow2 "$workdir/disk.qcow2"
cp -- "$firmware_vars" "$workdir/efivars.fd"
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
cpu=host
[[ $accelerator == kvm ]] || cpu=max

mkdir -p -- "$out/audit"
qemu-system-x86_64 \
	-machine "q35,accel=$accelerator" -cpu "$cpu" -smp 2 -m 2048 \
	-drive "if=pflash,format=raw,readonly=on,file=$firmware_code" \
	-drive "if=pflash,format=raw,file=$workdir/efivars.fd" \
	-drive "file=$workdir/disk.qcow2,if=virtio,format=qcow2" \
	-drive "file=$workdir/seed.iso,if=virtio,format=raw,readonly=on" \
	-netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=net0 \
	-display none -serial "file:$out/audit/console.log" \
	-daemonize -pidfile "$workdir/qemu.pid"
qemu_pid=$(cat "$workdir/qemu.pid")

echo "Waiting for SSH on 127.0.0.1:$port" >&2
ssh_opts=(-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR -i "$workdir/test_key" -p "$port")
for _ in $(seq 1 90); do
	if ssh "${ssh_opts[@]}" tester@127.0.0.1 true 2>/dev/null; then
		break
	fi
	sleep 5
done
ssh "${ssh_opts[@]}" tester@127.0.0.1 true

"${images[@]}" render "$image" "$target" --workdir "$workdir"
rm -f -- "$out"/audit/*.json
ANSIBLE_CONFIG="$repo/ansible.cfg" ansible-playbook \
	-i "127.0.0.1," \
	-e ansible_port="$port" -e ansible_user=tester -e ansible_ssh_private_key_file="$workdir/test_key" \
	-e ansible_become_password="$password" \
	-e "@$workdir/hardening.yml" \
	-e "@$workdir/tools.yml" \
	-e image_target="$target" \
	-e verify_audit_archive="$("${images[@]}" audit-archive "$image")" \
	-e verify_audit_binary="$("${images[@]}" audit-binary "$image")" \
	-e verify_audit_output="$out/audit/" \
	"$repo/ansible/verify.yml"

report=$(find "$out/audit" -maxdepth 1 -name '*.json' -print -quit)
[[ -n $report ]] || {
	echo "test.sh: the audit wrote no report" >&2
	exit 1
}
"${images[@]}" gate "$image" "$target" "$report" --summary "$out/audit/summary.md"

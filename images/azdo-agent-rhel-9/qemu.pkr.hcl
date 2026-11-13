# Target: QEMU, from the base image's finished qcow2. Packer copies it and
# boots it with a cloud-init seed that makes the build account, as a platform
# gives a new VM its first user. Output is a new qcow2 disk.
source "qemu" "image" {
  disk_image   = true
  iso_url      = var.base_image
  iso_checksum = var.base_image_checksum

  output_directory = var.output_directory
  vm_name          = "azdo-agent-rhel-9.qcow2"
  format           = "qcow2"
  disk_size        = var.disk_size
  disk_interface   = "virtio"
  disk_discard     = "unmap"
  # Compress the finished disk. The generalise step trims free space first.
  disk_compression   = true
  disk_detect_zeroes = "unmap"

  accelerator  = var.accelerator
  cpu_model    = var.cpu_model
  cpus         = var.cpus
  memory       = var.memory
  machine_type = "q35"
  net_device   = "virtio-net"
  headless     = var.headless

  efi_boot          = true
  efi_firmware_code = var.efi_firmware_code
  efi_firmware_vars = var.efi_firmware_vars

  # A NoCloud seed disk, which cloud-init finds by its label. The hardened
  # base allows no passwordless sudo, so the account gets a password for it,
  # in plain text for cloud-init to hash with the system's own method: the
  # seed exists only for the build.
  cd_label = "cidata"
  cd_content = {
    "meta-data" = yamlencode({ "instance-id" = "build", "local-hostname" = var.hostname })
    "user-data" = join("\n", ["#cloud-config", yamlencode({
      users = [{
        name                = var.build_username
        sudo                = "ALL=(ALL) ALL"
        shell               = "/bin/bash"
        lock_passwd         = false
        plain_text_passwd   = local.build_password
        ssh_authorized_keys = [var.ssh_public_key]
      }]
      ssh_pwauth = false
    })])
  }

  boot_wait = "5s"

  communicator           = "ssh"
  ssh_username           = var.build_username
  ssh_private_key_file   = var.ssh_private_key_file
  ssh_timeout            = "15m"
  ssh_handshake_attempts = 100

  # The generalise step leaves a script that deletes the build account,
  # resets machine identity and powers off.
  shutdown_command = "echo '${local.build_password}' | sudo -S /usr/local/sbin/image-finalise"
  shutdown_timeout = "10m"
}

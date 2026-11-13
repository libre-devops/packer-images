# Target: QEMU, installing from the ISO with UEFI. Output is a qcow2 disk.
source "qemu" "image" {
  iso_urls     = var.iso_urls
  iso_checksum = var.iso_checksum

  output_directory = var.output_directory
  vm_name          = "ubuntu-24.04.qcow2"
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

  # The autoinstall answers, as a NoCloud seed disk that cloud-init in the
  # installer finds by its label.
  cd_label = "cidata"
  cd_content = {
    "meta-data" = ""
    "user-data" = templatefile("${path.root}/autoinstall/user-data.pkrtpl.yaml", {
      hostname       = var.hostname
      username       = var.build_username
      password_hash  = local.build_password_hash
      ssh_public_key = var.ssh_public_key
      locale         = var.locale
      keyboard       = var.keyboard
      timezone       = var.timezone
    })
  }

  # Boot the installer from the GRUB prompt with `autoinstall` on the kernel
  # command line, so Subiquity does not stop to ask for confirmation.
  boot_wait = "5s"
  boot_command = [
    "c<wait2>",
    "linux /casper/vmlinuz autoinstall ---<enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>",
  ]

  communicator         = "ssh"
  ssh_username         = var.build_username
  ssh_private_key_file = var.ssh_private_key_file
  # The installer takes 10 to 15 minutes, and SSH only answers once the
  # installed system has rebooted.
  ssh_timeout            = "45m"
  ssh_handshake_attempts = 100

  # The generalise step leaves a script that deletes the build account,
  # resets machine identity and powers off.
  shutdown_command = "echo '${local.build_password}' | sudo -S /usr/local/sbin/image-finalise"
  shutdown_timeout = "10m"
}

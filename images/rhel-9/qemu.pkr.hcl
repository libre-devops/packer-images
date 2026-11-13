# Target: QEMU, installing from the ISO with UEFI. Output is a qcow2 disk.
source "qemu" "image" {
  iso_urls     = var.iso_urls
  iso_checksum = var.iso_checksum

  output_directory = var.output_directory
  vm_name          = "rhel-9.qcow2"
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

  # The kickstart, on a disc labelled OEMDRV: Anaconda loads ks.cfg from a
  # volume with that label without being told to.
  cd_label = "OEMDRV"
  cd_content = {
    "ks.cfg" = templatefile("${path.root}/kickstart/ks.pkrtpl.cfg", {
      hostname       = var.hostname
      username       = var.build_username
      password       = local.build_password
      ssh_public_key = var.ssh_public_key
      locale         = var.locale
      keyboard       = var.keyboard
      timezone       = var.timezone
    })
  }

  # The ISO's boot menu starts on "Test this media & install". Move up to
  # "Install" and start it. If the keys arrive late, the menu times out into
  # the media test and installs after it, which only takes longer.
  boot_wait    = "5s"
  boot_command = ["<up><wait><enter>"]

  communicator         = "ssh"
  ssh_username         = var.build_username
  ssh_private_key_file = var.ssh_private_key_file
  # SSH only answers once the installed system has rebooted.
  ssh_timeout            = "45m"
  ssh_handshake_attempts = 100

  # The generalise step leaves a script that deletes the build account,
  # resets machine identity and powers off.
  shutdown_command = "echo '${local.build_password}' | sudo -S /usr/local/sbin/image-finalise"
  shutdown_timeout = "10m"
}

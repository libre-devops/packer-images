# Inputs. `just build` writes the pinned values (ISO, hardening profile) and the
# per-build SSH key to a variables file from image.yml, so nothing here is
# site-specific. Override the hardware settings with PKR_VAR_<name>.

variable "iso_urls" {
  type        = list(string)
  description = "Where to download the installer ISO from, tried in order. From image.yml."
}

variable "iso_checksum" {
  type        = string
  description = "The ISO's checksum, as sha256:<hex>. From image.yml."
}

variable "output_directory" {
  type        = string
  description = "Where to write the image, its checksum and the build manifest."
}

variable "ssh_public_key" {
  type        = string
  description = "Public half of the key generated for this build only."
}

variable "ssh_private_key_file" {
  type        = string
  description = "Private half of the key generated for this build only."
}

variable "hardening_vars_file" {
  type        = string
  description = "The hardening profile rendered from hardening/common.yml and the target's file."
}

variable "tools_vars_file" {
  type        = string
  description = "The tools image.yml lists, rendered from tools/tools.yml."
}
variable "hardening_tags" {
  type        = string
  description = "The CIS profile, as the lockdown role tag that selects its controls."
}

variable "build_username" {
  type        = string
  default     = "packer"
  description = "The build account. The generalise step deletes it."
}

variable "hostname" {
  type        = string
  default     = "rhel-9"
  description = "Hostname during the build. Every VM built from the image gets its own from cloud-init."
}

variable "locale" {
  type    = string
  default = "en_GB.UTF-8"
}

variable "keyboard" {
  type    = string
  default = "gb"
}

variable "timezone" {
  type    = string
  default = "Etc/UTC"
}

variable "cpu_model" {
  type        = string
  default     = "host"
  description = "host with kvm. QEMU's own default CPU is too old for RHEL 9, which needs x86-64-v2; use max with tcg."
}

variable "cpus" {
  type    = number
  default = 2
}

variable "memory" {
  type        = number
  default     = 4096
  description = "MiB."
}

variable "disk_size" {
  type        = string
  default     = "32G"
  description = "Big enough for the volumes in kickstart/ks.pkrtpl.cfg."
}

variable "accelerator" {
  type        = string
  default     = "kvm"
  description = "kvm, or tcg where there is no /dev/kvm (very slow)."
}

variable "headless" {
  type    = bool
  default = true
}

variable "efi_firmware_code" {
  type        = string
  default     = "/usr/share/OVMF/OVMF_CODE_4M.fd"
  description = "UEFI firmware, from the ovmf package on Debian and Ubuntu."
}

variable "efi_firmware_vars" {
  type    = string
  default = "/usr/share/OVMF/OVMF_VARS_4M.fd"
}

# Inputs. `just build` writes the base image's disk and checksum, the per-build
# SSH key and the rendered tool list to a variables file, so nothing here is
# site-specific. Override the hardware settings with PKR_VAR_<name>.
variable "base_image" {
  type        = string
  description = "The base image's finished qcow2, from its own build."
}
variable "base_image_checksum" {
  type        = string
  description = "The base image's checksum, as sha256:<hex>, from its build."
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
variable "tools_vars_file" {
  type        = string
  description = "The tools image.yml lists, rendered from tools/tools.yml."
}
variable "build_username" {
  type        = string
  default     = "packer"
  description = "The build account, made by the cloud-init seed. The generalise step deletes it."
}
variable "hostname" {
  type        = string
  default     = "gh-runner"
  description = "Hostname during the build. Every VM built from the image gets its own from cloud-init."
}
variable "cpu_model" {
  type        = string
  default     = "host"
  description = "host with kvm; use max with tcg. RHEL 9 needs x86-64-v2, which QEMU's own default CPU is not."
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
  description = "At least the base image's disk size."
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

variable "bastion_public_ip" {
  description = "Public IP address of the bastion host"
  type        = string
}

variable "machines" {
  description = "List of machine names to configure SSH access for"
  type        = list(string)
}

variable "machine_private_ips" {
  description = "Map of machine names to their private IPs"
  type        = map(string)
}

variable "ssh_user" {
  description = "SSH user to use for connections"
  type        = string
}

variable "ssh_key_path" {
  description = "Path to the SSH private key file"
  type        = string
} 
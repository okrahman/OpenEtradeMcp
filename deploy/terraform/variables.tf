variable "project_id" { type = string }
variable "region" {
  type    = string
  default = "us-east4"
}
variable "zone" {
  type    = string
  default = "us-east4-a"
}
variable "machine_type" {
  type    = string
  default = "e2-medium"
}
variable "domain" { type = string }
variable "owner_subject" { type = string }
variable "google_client_id" { type = string }
variable "bundle_bucket" { type = string }
variable "bundle_object" { type = string }
variable "bundle_sha256" {
  type = string
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.bundle_sha256))
    error_message = "Pin the deployment bundle SHA256."
  }
}
variable "secret_ids" {
  description = "Secret Manager identifiers only. Never pass secret payloads to Terraform."
  type        = map(string)
  validation {
    condition     = alltrue([for key in keys(var.secret_ids) : can(regex("^(ingress|mcp|authorization|gateway|brokerage-proxy|identity-proxy)/[a-zA-Z0-9._-]+$", key))])
    error_message = "Secret destination must name its owning container and a simple filename."
  }
}
variable "operator_email" { type = string }
variable "alert_email" { type = string }
variable "images" {
  type = map(string)
  validation {
    condition     = alltrue([for image in values(var.images) : can(regex("@sha256:[a-f0-9]{64}$", image))])
    error_message = "Every service image must be digest pinned."
  }
}

variable "manage_secret_containers" {
  type        = bool
  default     = false
  description = "Create empty Secret Manager containers; leave false for existing secrets. No payloads enter state."
}

locals {
  services = toset(["compute.googleapis.com", "secretmanager.googleapis.com", "artifactregistry.googleapis.com", "logging.googleapis.com", "monitoring.googleapis.com", "iap.googleapis.com", "storage.googleapis.com", "oslogin.googleapis.com"])
}
resource "google_project_service" "apis" {
  for_each           = local.services
  service            = each.value
  disable_on_destroy = false
}
resource "google_compute_network" "mcp" {
  name                    = "etrade-mcp"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}
resource "google_compute_subnetwork" "mcp" {
  name                     = "etrade-mcp"
  ip_cidr_range            = "10.42.0.0/24"
  region                   = var.region
  network                  = google_compute_network.mcp.id
  private_ip_google_access = true
}
resource "google_compute_address" "public" { name = "etrade-mcp" }
resource "google_compute_firewall" "https" {
  name          = "etrade-mcp-https"
  network       = google_compute_network.mcp.name
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["etrade-mcp"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}
resource "google_compute_firewall" "iap_ssh" {
  name          = "etrade-mcp-iap-ssh"
  network       = google_compute_network.mcp.name
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["etrade-mcp"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
resource "google_service_account" "host" {
  account_id   = "etrade-mcp-host"
  display_name = "Etrade host bootstrap and telemetry"
}
resource "google_project_iam_member" "telemetry" {
  for_each = toset(["roles/logging.logWriter", "roles/monitoring.metricWriter"])
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.host.email}"
}
resource "google_secret_manager_secret_iam_member" "startup" {
  for_each   = toset(values(var.secret_ids))
  project    = var.project_id
  secret_id  = each.value
  role       = "roles/secretmanager.secretAccessor"
  member     = "serviceAccount:${google_service_account.host.email}"
  depends_on = [google_project_service.apis, google_secret_manager_secret.containers]
}
resource "google_storage_bucket_iam_member" "bundle" {
  bucket = var.bundle_bucket
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.host.email}"
}
resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = "etrade-mcp"
  format        = "DOCKER"
  depends_on    = [google_project_service.apis]
}
resource "google_compute_disk" "state" {
  name = "etrade-mcp-state"
  type = "pd-balanced"
  zone = var.zone
  size = 20
  # GCE encrypts persistent disks at rest with Google-managed keys.
  lifecycle { prevent_destroy = true }
}
resource "google_compute_instance" "mcp" {
  name                = "etrade-mcp"
  machine_type        = var.machine_type
  zone                = var.zone
  tags                = ["etrade-mcp"]
  deletion_protection = true
  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = 20
      type  = "pd-balanced"
    }
  }
  attached_disk {
    source      = google_compute_disk.state.id
    device_name = "etrade-state"
  }
  network_interface {
    subnetwork = google_compute_subnetwork.mcp.id
    access_config { nat_ip = google_compute_address.public.address }
  }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
  service_account {
    email  = google_service_account.host.email
    scopes = ["cloud-platform"]
  }
  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    startup-script = templatefile("${path.module}/startup.sh.tftpl", {
      region       = var.region, project = var.project_id, bucket = var.bundle_bucket, object = var.bundle_object, sha256 = var.bundle_sha256,
      domain       = var.domain, owner = var.owner_subject, google_client = var.google_client_id,
      secrets_json = jsonencode(var.secret_ids), images_json = jsonencode(var.images)
    })
  }
  depends_on = [google_secret_manager_secret_iam_member.startup, google_storage_bucket_iam_member.bundle, google_project_iam_member.telemetry, google_artifact_registry_repository_iam_member.host_reader]
}
resource "google_project_iam_member" "oslogin" {
  project = var.project_id
  role    = "roles/compute.osAdminLogin"
  member  = "user:${var.operator_email}"
}
resource "google_iap_tunnel_instance_iam_member" "ssh" {
  project  = var.project_id
  zone     = var.zone
  instance = google_compute_instance.mcp.name
  role     = "roles/iap.tunnelResourceAccessor"
  member   = "user:${var.operator_email}"
}
resource "google_logging_project_bucket_config" "audit" {
  project        = var.project_id
  location       = "global"
  bucket_id      = "etrade-audit"
  retention_days = 30
}
resource "google_logging_project_sink" "audit" {
  name                   = "etrade-audit"
  destination            = "logging.googleapis.com/projects/${var.project_id}/locations/global/buckets/${google_logging_project_bucket_config.audit.bucket_id}"
  filter                 = "resource.type=\"gce_instance\" AND labels.\"compute.googleapis.com/resource_name\"=\"etrade-mcp\""
  unique_writer_identity = true
}
resource "google_project_iam_member" "audit_writer" {
  project = var.project_id
  role    = "roles/logging.bucketWriter"
  member  = google_logging_project_sink.audit.writer_identity
}
resource "google_monitoring_notification_channel" "owner" {
  display_name = "Etrade owner"
  type         = "email"
  labels       = { email_address = var.alert_email }
}
resource "google_logging_metric" "security" {
  name   = "etrade_security_events"
  filter = "resource.type=\"gce_instance\" AND (jsonPayload.action=\"policy_denied\" OR jsonPayload.action=\"service_unavailable\" OR jsonPayload.action=\"reauthorization_required\")"
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}
resource "google_monitoring_alert_policy" "security" {
  display_name          = "Etrade denial, failure or reauthorization"
  combiner              = "OR"
  notification_channels = [google_monitoring_notification_channel.owner.name]
  conditions {
    display_name = "Security event"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.security.name}\" AND resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
}
resource "google_monitoring_uptime_check_config" "https" {
  display_name = "Etrade HTTPS metadata"
  timeout      = "10s"
  http_check {
    path         = "/.well-known/oauth-protected-resource"
    port         = 443
    use_ssl      = true
    validate_ssl = true
  }
  monitored_resource {
    type   = "uptime_url"
    labels = { project_id = var.project_id, host = var.domain }
  }
}
resource "google_monitoring_alert_policy" "availability" {
  display_name          = "Etrade HTTPS unavailable"
  combiner              = "OR"
  notification_channels = [google_monitoring_notification_channel.owner.name]
  conditions {
    display_name = "HTTPS metadata unavailable for two minutes"
    condition_threshold {
      filter          = "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" AND resource.type=\"uptime_url\" AND metric.label.check_id=\"${google_monitoring_uptime_check_config.https.uptime_check_id}\""
      comparison      = "COMPARISON_LT"
      threshold_value = 1
      duration        = "120s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_FRACTION_TRUE"
      }
    }
  }
}
output "public_ip" { value = google_compute_address.public.address }
output "artifact_registry" { value = google_artifact_registry_repository.images.name }

resource "google_artifact_registry_repository_iam_member" "host_reader" {
  location   = var.region
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.host.email}"
}

resource "google_secret_manager_secret" "containers" {
  for_each  = var.manage_secret_containers ? toset(values(var.secret_ids)) : toset([])
  secret_id = each.value
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
  lifecycle { prevent_destroy = true }
}

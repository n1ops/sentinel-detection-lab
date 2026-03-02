variable "workspace_id" {
  description = "Sentinel onboarding workspace ID for analytics rules"
  type        = string
}

variable "detections_path" {
  description = "Path to the detections directory containing KQL files"
  type        = string
}

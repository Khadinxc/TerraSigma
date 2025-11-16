resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_camera_and_microphone_access" {
  name                       = "suspicious_camera_and_microphone_access"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Camera and Microphone Access"
  description                = "Detects Processes accessing the camera and microphone from suspicious folder - Unlikely, there could be conferencing software running from a Temp folder accessing the devices"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore*" and RegistryKey contains "\\NonPackaged") and (RegistryKey contains "microphone" or RegistryKey contains "webcam") and (RegistryKey contains ":#Windows#Temp#" or RegistryKey contains ":#$Recycle.bin#" or RegistryKey contains ":#Temp#" or RegistryKey contains ":#Users#Public#" or RegistryKey contains ":#Users#Default#" or RegistryKey contains ":#Users#Desktop#")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1125", "T1123"]
  enabled                    = true

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = []
      by_alert_details        = []
      by_custom_details       = []
    }
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  entity_mapping {
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}
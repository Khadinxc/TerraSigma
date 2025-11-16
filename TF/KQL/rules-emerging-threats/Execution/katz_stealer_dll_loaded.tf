resource "azurerm_sentinel_alert_rule_scheduled" "katz_stealer_dll_loaded" {
  name                       = "katz_stealer_dll_loaded"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Katz Stealer DLL Loaded"
  description                = "Detects loading of DLLs associated with Katz Stealer malware 2025 variants. Katz Stealer is a malware variant that is known to be used for stealing sensitive information from compromised systems. The process that loads these DLLs are very likely to be malicious. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\katz_ontop.dll" or FolderPath endswith "\\AppData\\Local\\Temp\\received_dll.dll"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1129"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
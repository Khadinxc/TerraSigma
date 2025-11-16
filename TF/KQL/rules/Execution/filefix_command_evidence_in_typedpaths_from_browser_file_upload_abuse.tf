resource "azurerm_sentinel_alert_rule_scheduled" "filefix_command_evidence_in_typedpaths_from_browser_file_upload_abuse" {
  name                       = "filefix_command_evidence_in_typedpaths_from_browser_file_upload_abuse"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "FileFix - Command Evidence in TypedPaths from Browser File Upload Abuse"
  description                = "Detects commonly-used chained commands and strings in the most recent 'url' value of the 'TypedPaths' key, which could be indicative of a user being targeted by the FileFix technique."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains "#" and (InitiatingProcessFolderPath endswith "\\brave.exe" or InitiatingProcessFolderPath endswith "\\chrome.exe" or InitiatingProcessFolderPath endswith "\\firefox.exe" or InitiatingProcessFolderPath endswith "\\msedge.exe") and RegistryKey endswith "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\\url1") and (RegistryValueData contains "cmd" or RegistryValueData contains "curl" or RegistryValueData contains "powershell" or RegistryValueData contains "bitsadmin" or RegistryValueData contains "certutil" or RegistryValueData contains "mshta" or RegistryValueData contains "regsvr32")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1204"]
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
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}
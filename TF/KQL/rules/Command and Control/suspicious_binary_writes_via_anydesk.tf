resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_binary_writes_via_anydesk" {
  name                       = "suspicious_binary_writes_via_anydesk"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Binary Writes Via AnyDesk"
  description                = "Detects AnyDesk writing binary files to disk other than \"gcapi.dll\". According to RedCanary research it is highly abnormal for AnyDesk to write executable files to disk besides gcapi.dll, which is a legitimate DLL that is part of the Google Chrome web browser used to interact with the Google Cloud API. (See reference section for more details)"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where ((InitiatingProcessFolderPath endswith "\\AnyDesk.exe" or InitiatingProcessFolderPath endswith "\\AnyDeskMSI.exe") and (FolderPath endswith ".dll" or FolderPath endswith ".exe")) and (not(FolderPath endswith "\\gcapi.dll"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1219"]
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
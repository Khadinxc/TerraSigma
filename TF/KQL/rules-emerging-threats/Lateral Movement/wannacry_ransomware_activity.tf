resource "azurerm_sentinel_alert_rule_scheduled" "wannacry_ransomware_activity" {
  name                       = "wannacry_ransomware_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WannaCry Ransomware Activity"
  description                = "Detects WannaCry ransomware activity"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "@Please_Read_Me@.txt" or ((FolderPath endswith "\\tasksche.exe" or FolderPath endswith "\\mssecsvc.exe" or FolderPath endswith "\\taskdl.exe" or FolderPath endswith "\\taskhsvc.exe" or FolderPath endswith "\\taskse.exe" or FolderPath endswith "\\111.exe" or FolderPath endswith "\\lhdfrgui.exe" or FolderPath endswith "\\linuxnew.exe" or FolderPath endswith "\\wannacry.exe") or FolderPath contains "WanaDecryptor")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement", "Discovery", "DefenseEvasion", "Impact"]
  techniques                 = ["T1210", "T1083", "T1222", "T1486", "T1490"]
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
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
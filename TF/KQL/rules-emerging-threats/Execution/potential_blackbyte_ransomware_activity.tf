resource "azurerm_sentinel_alert_rule_scheduled" "potential_blackbyte_ransomware_activity" {
  name                       = "potential_blackbyte_ransomware_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential BlackByte Ransomware Activity"
  description                = "Detects command line patterns used by BlackByte ransomware in different operations"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -single " and FolderPath startswith "C:\\Users\\Public\\") or (ProcessCommandLine contains "del C:\\Windows\\System32\\Taskmgr.exe" or ProcessCommandLine contains ";Set-Service -StartupType Disabled $" or ProcessCommandLine contains "powershell -command \"$x =[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(" or ProcessCommandLine contains " do start wordpad.exe /p ")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion", "Impact"]
  techniques                 = ["T1485", "T1498", "T1059", "T1140"]
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
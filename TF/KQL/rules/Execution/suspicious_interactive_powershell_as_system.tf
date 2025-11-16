resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_interactive_powershell_as_system" {
  name                       = "suspicious_interactive_powershell_as_system"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Interactive PowerShell as SYSTEM"
  description                = "Detects the creation of files that indicator an interactive use of PowerShell in the SYSTEM user context - Administrative activity - PowerShell scripts running as SYSTEM user"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath in~ ("C:\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\StartupProfileData-Interactive")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_get_variable_exe_creation" {
  name                       = "suspicious_get_variable_exe_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Get-Variable.exe Creation"
  description                = "Get-Variable is a valid PowerShell cmdlet WindowsApps is by default in the path where PowerShell is executed. So when the Get-Variable command is issued on PowerShell execution, the system first looks for the Get-Variable executable in the path and executes the malicious binary instead of looking for the PowerShell cmdlet."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "Local\\Microsoft\\WindowsApps\\Get-Variable.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "DefenseEvasion"]
  techniques                 = ["T1546", "T1027"]
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
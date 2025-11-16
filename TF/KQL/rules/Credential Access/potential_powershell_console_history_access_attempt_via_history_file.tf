resource "azurerm_sentinel_alert_rule_scheduled" "potential_powershell_console_history_access_attempt_via_history_file" {
  name                       = "potential_powershell_console_history_access_attempt_via_history_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential PowerShell Console History Access Attempt via History File"
  description                = "Detects potential access attempts to the PowerShell console history directly via history file (ConsoleHost_history.txt). This can give access to plaintext passwords used in PowerShell commands or used for general reconnaissance. - Legitimate access of the console history file is possible"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "ConsoleHost_history.txt" or ProcessCommandLine contains "(Get-PSReadLineOption).HistorySavePath"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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
  }
}
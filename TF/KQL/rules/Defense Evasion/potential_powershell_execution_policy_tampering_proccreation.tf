resource "azurerm_sentinel_alert_rule_scheduled" "potential_powershell_execution_policy_tampering_proccreation" {
  name                       = "potential_powershell_execution_policy_tampering_proccreation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential PowerShell Execution Policy Tampering - ProcCreation"
  description                = "Detects changes to the PowerShell execution policy registry key in order to bypass signing requirements for script execution from the CommandLine"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy" or ProcessCommandLine contains "\\Policies\\Microsoft\\Windows\\PowerShell\\ExecutionPolicy") and (ProcessCommandLine contains "Bypass" or ProcessCommandLine contains "RemoteSigned" or ProcessCommandLine contains "Unrestricted")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
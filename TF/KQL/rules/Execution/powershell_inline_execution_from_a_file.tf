resource "azurerm_sentinel_alert_rule_scheduled" "powershell_inline_execution_from_a_file" {
  name                       = "powershell_inline_execution_from_a_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Powershell Inline Execution From A File"
  description                = "Detects inline execution of PowerShell code from a file"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "iex " or ProcessCommandLine contains "Invoke-Expression " or ProcessCommandLine contains "Invoke-Command " or ProcessCommandLine contains "icm ") and ProcessCommandLine contains " -raw" and (ProcessCommandLine contains "cat " or ProcessCommandLine contains "get-content " or ProcessCommandLine contains "type ")
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}
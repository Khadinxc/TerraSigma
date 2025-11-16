resource "azurerm_sentinel_alert_rule_scheduled" "powershell_get_clipboard_cmdlet_via_cli" {
  name                       = "powershell_get_clipboard_cmdlet_via_cli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Get-Clipboard Cmdlet Via CLI"
  description                = "Detects usage of the 'Get-Clipboard' cmdlet via CLI"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "Get-Clipboard"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1115"]
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
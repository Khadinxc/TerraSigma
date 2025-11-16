resource "azurerm_sentinel_alert_rule_scheduled" "powershell_get_process_lsass" {
  name                       = "powershell_get_process_lsass"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Get-Process LSASS"
  description                = "Detects a \"Get-Process\" cmdlet and it's aliases on lsass process, which is in almost all cases a sign of malicious activity"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "Get-Process lsas" or ProcessCommandLine contains "ps lsas" or ProcessCommandLine contains "gps lsas"
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
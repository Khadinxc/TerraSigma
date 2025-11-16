resource "azurerm_sentinel_alert_rule_scheduled" "powershell_sam_copy" {
  name                       = "powershell_sam_copy"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell SAM Copy"
  description                = "Detects suspicious PowerShell scripts accessing SAM hives - Some rare backup scenarios - PowerShell scripts fixing HiveNightmare / SeriousSAM ACLs"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\HarddiskVolumeShadowCopy" and ProcessCommandLine contains "System32\\config\\sam") and (ProcessCommandLine contains "Copy-Item" or ProcessCommandLine contains "cp $_." or ProcessCommandLine contains "cpi $_." or ProcessCommandLine contains "copy $_." or ProcessCommandLine contains ".File]::Copy(")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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
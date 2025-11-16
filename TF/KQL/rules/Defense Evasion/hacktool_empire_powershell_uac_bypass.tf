resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_empire_powershell_uac_bypass" {
  name                       = "hacktool_empire_powershell_uac_bypass"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Empire PowerShell UAC Bypass"
  description                = "Detects some Empire PowerShell UAC bypass methods"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update)" or ProcessCommandLine contains " -NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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
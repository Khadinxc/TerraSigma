resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_winpwn_execution" {
  name                       = "hacktool_winpwn_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - WinPwn Execution"
  description                = "Detects commandline keywords indicative of potential usge of the tool WinPwn. A tool for Windows and Active Directory reconnaissance and exploitation."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "Offline_Winpwn" or ProcessCommandLine contains "WinPwn " or ProcessCommandLine contains "WinPwn.exe" or ProcessCommandLine contains "WinPwn.ps1"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess", "DefenseEvasion", "Discovery", "Execution", "PrivilegeEscalation"]
  techniques                 = ["T1046", "T1082", "T1106", "T1518", "T1548", "T1552", "T1555"]
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
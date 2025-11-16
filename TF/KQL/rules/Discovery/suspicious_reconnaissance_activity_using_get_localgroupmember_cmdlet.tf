resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_reconnaissance_activity_using_get_localgroupmember_cmdlet" {
  name                       = "suspicious_reconnaissance_activity_using_get_localgroupmember_cmdlet"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet"
  description                = "Detects suspicious reconnaissance command line activity on Windows systems using the PowerShell Get-LocalGroupMember Cmdlet - Administrative activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "Get-LocalGroupMember " and (ProcessCommandLine contains "domain admins" or ProcessCommandLine contains " administrator" or ProcessCommandLine contains " administrateur" or ProcessCommandLine contains "enterprise admins" or ProcessCommandLine contains "Exchange Trusted Subsystem" or ProcessCommandLine contains "Remote Desktop Users" or ProcessCommandLine contains "Utilisateurs du Bureau à distance" or ProcessCommandLine contains "Usuarios de escritorio remoto")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1087"]
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
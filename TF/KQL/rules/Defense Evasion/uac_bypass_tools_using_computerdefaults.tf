resource "azurerm_sentinel_alert_rule_scheduled" "uac_bypass_tools_using_computerdefaults" {
  name                       = "uac_bypass_tools_using_computerdefaults"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Bypass Tools Using ComputerDefaults"
  description                = "Detects tools such as UACMe used to bypass UAC with computerdefaults.exe (UACMe 59)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath =~ "C:\\Windows\\System32\\ComputerDefaults.exe" and (ProcessIntegrityLevel in~ ("High", "System", "S-1-16-16384", "S-1-16-12288"))) and (not((InitiatingProcessFolderPath contains ":\\Windows\\System32" or InitiatingProcessFolderPath contains ":\\Program Files")))
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
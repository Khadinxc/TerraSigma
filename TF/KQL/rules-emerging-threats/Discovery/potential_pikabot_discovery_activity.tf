resource "azurerm_sentinel_alert_rule_scheduled" "potential_pikabot_discovery_activity" {
  name                       = "potential_pikabot_discovery_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Pikabot Discovery Activity"
  description                = "Detects system discovery activity carried out by Pikabot, such as incl. network, user info and domain groups. The malware Pikabot has been seen to use this technique as part of its C2-botnet registration with a short collection time frame (less than 1 minute). - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine in~ ("ipconfig.exe /all", "netstat.exe -aon", "whoami.exe /all")) and (InitiatingProcessParentFileName endswith "\\rundll32.exe" or (InitiatingProcessFolderPath endswith "\\SearchFilterHost.exe" or InitiatingProcessFolderPath endswith "\\SearchProtocolHost.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1016", "T1049", "T1087"]
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
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
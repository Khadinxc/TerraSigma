resource "azurerm_sentinel_alert_rule_scheduled" "potential_pikabot_hollowing_activity" {
  name                       = "potential_pikabot_hollowing_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Pikabot Hollowing Activity"
  description                = "Detects the execution of rundll32 that leads to the invocation of legitimate Windows binaries. The malware Pikabot has been seen to use this technique for process hollowing through hard-coded Windows binaries - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\SearchFilterHost.exe" or FolderPath endswith "\\SearchProtocolHost.exe" or FolderPath endswith "\\sndvol.exe" or FolderPath endswith "\\wermgr.exe" or FolderPath endswith "\\wwahost.exe") and InitiatingProcessFolderPath endswith "\\rundll32.exe") and (not((FolderPath endswith "\\sndvol.exe" and InitiatingProcessCommandLine contains "mmsys.cpl")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1055"]
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
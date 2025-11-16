resource "azurerm_sentinel_alert_rule_scheduled" "hidden_powershell_in_link_file_pattern" {
  name                       = "hidden_powershell_in_link_file_pattern"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Hidden Powershell in Link File Pattern"
  description                = "Detects events that appear when a user click on a link file with a powershell command in it - Legitimate commands in .lnk files"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "powershell" and ProcessCommandLine contains ".lnk") and FolderPath =~ "C:\\Windows\\System32\\cmd.exe" and InitiatingProcessFolderPath =~ "C:\\Windows\\explorer.exe"
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
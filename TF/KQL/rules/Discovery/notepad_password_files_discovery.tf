resource "azurerm_sentinel_alert_rule_scheduled" "notepad_password_files_discovery" {
  name                       = "notepad_password_files_discovery"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Notepad Password Files Discovery"
  description                = "Detects the execution of Notepad to open a file that has the string \"password\" which may indicate unauthorized access to credentials or suspicious activity. - Legitimate use of opening files from remote hosts by administrators or users. However, storing passwords in text readable format could potentially be a violation of the organization's policy. Any match should be investigated further."
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "password" and ProcessCommandLine contains ".txt") or (ProcessCommandLine contains "password" and ProcessCommandLine contains ".csv") or (ProcessCommandLine contains "password" and ProcessCommandLine contains ".doc") or (ProcessCommandLine contains "password" and ProcessCommandLine contains ".xls")) and FolderPath endswith "\\notepad.exe" and InitiatingProcessFolderPath endswith "\\explorer.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1083"]
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
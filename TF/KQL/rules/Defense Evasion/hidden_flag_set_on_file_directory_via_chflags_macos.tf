resource "azurerm_sentinel_alert_rule_scheduled" "hidden_flag_set_on_file_directory_via_chflags_macos" {
  name                       = "hidden_flag_set_on_file_directory_via_chflags_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Hidden Flag Set On File/Directory Via Chflags - MacOS"
  description                = "Detects the execution of the \"chflags\" utility with the \"hidden\" flag, in order to hide files on MacOS. When a file or directory has this hidden flag set, it becomes invisible to the default file listing commands and in graphical file browsers. - Legitimate usage of chflags by administrators and users."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "hidden " and FolderPath endswith "/chflags"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess", "CommandAndControl"]
  techniques                 = ["T1218", "T1564", "T1552", "T1105"]
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
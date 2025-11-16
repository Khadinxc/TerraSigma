resource "azurerm_sentinel_alert_rule_scheduled" "access_of_sudoers_file_content" {
  name                       = "access_of_sudoers_file_content"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Access of Sudoers File Content"
  description                = "Detects the execution of a text-based file access or inspection utilities to read the content of /etc/sudoers in order to potentially list all users that have sudo rights. - Legitimate administration activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " /etc/sudoers" and (FolderPath endswith "/cat" or FolderPath endswith "/ed" or FolderPath endswith "/egrep" or FolderPath endswith "/emacs" or FolderPath endswith "/fgrep" or FolderPath endswith "/grep" or FolderPath endswith "/head" or FolderPath endswith "/less" or FolderPath endswith "/more" or FolderPath endswith "/nano" or FolderPath endswith "/tail")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Reconnaissance"]
  techniques                 = ["T1592"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "file_and_subfolder_enumeration_via_dir_command" {
  name                       = "file_and_subfolder_enumeration_via_dir_command"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File And SubFolder Enumeration Via Dir Command"
  description                = "Detects usage of the \"dir\" command part of Windows CMD with the \"/S\" command line flag in order to enumerate files in a specified directory and all subdirectories. - Likely"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine =~ "*dir*-s*" or ProcessCommandLine =~ "*dir*/s*" or ProcessCommandLine =~ "*dir*–s*" or ProcessCommandLine =~ "*dir*—s*" or ProcessCommandLine =~ "*dir*―s*") and (FolderPath endswith "\\cmd.exe" or ProcessVersionInfoOriginalFileName =~ "Cmd.Exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1217"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "copy_dmp_dump_files_from_remote_share_via_cmd_exe" {
  name                       = "copy_dmp_dump_files_from_remote_share_via_cmd_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE"
  description                = "Detects usage of the copy builtin cmd command to copy files with the \".dmp\"/\".dump\" extension from a remote share"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains ".dmp" or ProcessCommandLine contains ".dump" or ProcessCommandLine contains ".hdmp") and (ProcessCommandLine contains "copy " and ProcessCommandLine contains " \\\\")) and (FolderPath endswith "\\cmd.exe" or ProcessVersionInfoOriginalFileName =~ "Cmd.Exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
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
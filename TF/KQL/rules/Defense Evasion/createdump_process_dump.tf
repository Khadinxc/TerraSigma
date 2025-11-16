resource "azurerm_sentinel_alert_rule_scheduled" "createdump_process_dump" {
  name                       = "createdump_process_dump"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "CreateDump Process Dump"
  description                = "Detects uses of the createdump.exe LOLOBIN utility to dump process memory - Command lines that use the same flags"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -u " or ProcessCommandLine contains " --full " or ProcessCommandLine contains " -f " or ProcessCommandLine contains " --name " or ProcessCommandLine contains ".dmp ") and (FolderPath endswith "\\createdump.exe" or ProcessVersionInfoOriginalFileName =~ "FX_VER_INTERNALNAME_STR")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess"]
  techniques                 = ["T1036", "T1003"]
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
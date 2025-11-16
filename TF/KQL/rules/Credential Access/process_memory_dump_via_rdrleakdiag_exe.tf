resource "azurerm_sentinel_alert_rule_scheduled" "process_memory_dump_via_rdrleakdiag_exe" {
  name                       = "process_memory_dump_via_rdrleakdiag_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Memory Dump via RdrLeakDiag.EXE"
  description                = "Detects the use of the Microsoft Windows Resource Leak Diagnostic tool \"rdrleakdiag.exe\" to dump process memory - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-memdmp" or ProcessCommandLine contains "/memdmp" or ProcessCommandLine contains "–memdmp" or ProcessCommandLine contains "—memdmp" or ProcessCommandLine contains "―memdmp" or ProcessCommandLine contains "fullmemdmp") and (ProcessCommandLine contains " -o " or ProcessCommandLine contains " /o " or ProcessCommandLine contains " –o " or ProcessCommandLine contains " —o " or ProcessCommandLine contains " ―o " or ProcessCommandLine contains " -p " or ProcessCommandLine contains " /p " or ProcessCommandLine contains " –p " or ProcessCommandLine contains " —p " or ProcessCommandLine contains " ―p ") and (FolderPath endswith "\\rdrleakdiag.exe" or ProcessVersionInfoOriginalFileName =~ "RdrLeakDiag.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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
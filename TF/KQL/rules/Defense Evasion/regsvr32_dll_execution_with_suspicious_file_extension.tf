resource "azurerm_sentinel_alert_rule_scheduled" "regsvr32_dll_execution_with_suspicious_file_extension" {
  name                       = "regsvr32_dll_execution_with_suspicious_file_extension"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Regsvr32 DLL Execution With Suspicious File Extension"
  description                = "Detects the execution of REGSVR32.exe with DLL files masquerading as other files - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine endswith ".bin" or ProcessCommandLine endswith ".bmp" or ProcessCommandLine endswith ".cr2" or ProcessCommandLine endswith ".dat" or ProcessCommandLine endswith ".eps" or ProcessCommandLine endswith ".gif" or ProcessCommandLine endswith ".ico" or ProcessCommandLine endswith ".jpeg" or ProcessCommandLine endswith ".jpg" or ProcessCommandLine endswith ".log" or ProcessCommandLine endswith ".nef" or ProcessCommandLine endswith ".orf" or ProcessCommandLine endswith ".png" or ProcessCommandLine endswith ".raw" or ProcessCommandLine endswith ".rtf" or ProcessCommandLine endswith ".sr2" or ProcessCommandLine endswith ".temp" or ProcessCommandLine endswith ".tif" or ProcessCommandLine endswith ".tiff" or ProcessCommandLine endswith ".tmp" or ProcessCommandLine endswith ".txt") and (FolderPath endswith "\\regsvr32.exe" or ProcessVersionInfoOriginalFileName =~ "REGSVR32.EXE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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
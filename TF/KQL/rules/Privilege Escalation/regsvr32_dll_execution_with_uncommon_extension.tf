resource "azurerm_sentinel_alert_rule_scheduled" "regsvr32_dll_execution_with_uncommon_extension" {
  name                       = "regsvr32_dll_execution_with_uncommon_extension"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Regsvr32 DLL Execution With Uncommon Extension"
  description                = "Detects a \"regsvr32\" execution where the DLL doesn't contain a common file extension. - Other legitimate extensions currently not in the list either from third party or specific Windows components."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\regsvr32.exe" or ProcessVersionInfoOriginalFileName =~ "REGSVR32.EXE") and (not((ProcessCommandLine =~ "" or (ProcessCommandLine contains ".ax" or ProcessCommandLine contains ".cpl" or ProcessCommandLine contains ".dll" or ProcessCommandLine contains ".ocx") or isnull(ProcessCommandLine)))) and (not((ProcessCommandLine contains ".bav" or ProcessCommandLine contains ".ppl")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "DefenseEvasion", "Execution"]
  techniques                 = ["T1574"]
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
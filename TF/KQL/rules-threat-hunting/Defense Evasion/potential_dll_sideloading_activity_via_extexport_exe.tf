resource "azurerm_sentinel_alert_rule_scheduled" "potential_dll_sideloading_activity_via_extexport_exe" {
  name                       = "potential_dll_sideloading_activity_via_extexport_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential DLL Sideloading Activity Via ExtExport.EXE"
  description                = "Detects the execution of \"Extexport.exe\".A utility that is part of the Internet Explorer browser and is used to export and import various settings and data, particularly when switching between Internet Explorer and other web browsers like Firefox. It allows users to transfer bookmarks, browsing history, and other preferences from Internet Explorer to Firefox or vice versa. It can be abused as a tool to side load any DLL. If a folder is provided in the command line it'll load any DLL with one of the following names \"mozcrt19.dll\", \"mozsqlite3.dll\", or \"sqlite.dll\". Arbitrary DLLs can also be loaded if a specific number of flags was provided."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\Extexport.exe" or ProcessVersionInfoOriginalFileName =~ "extexport.exe"
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
resource "azurerm_sentinel_alert_rule_scheduled" "loaded_module_enumeration_via_tasklist_exe" {
  name                       = "loaded_module_enumeration_via_tasklist_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Loaded Module Enumeration Via Tasklist.EXE"
  description                = "Detects the enumeration of a specific DLL or EXE being used by a binary via \"tasklist.exe\". This is often used by attackers in order to find the specific process identifier (PID) that is using the DLL in question. In order to dump the process memory or perform other nefarious actions."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-m" or ProcessCommandLine contains "/m" or ProcessCommandLine contains "–m" or ProcessCommandLine contains "—m" or ProcessCommandLine contains "―m") and (FolderPath endswith "\\tasklist.exe" or ProcessVersionInfoOriginalFileName =~ "tasklist.exe") and ProcessCommandLine contains "rdpcorets.dll"
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
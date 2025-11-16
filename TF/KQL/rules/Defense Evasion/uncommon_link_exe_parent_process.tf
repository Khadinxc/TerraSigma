resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_link_exe_parent_process" {
  name                       = "uncommon_link_exe_parent_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Link.EXE Parent Process"
  description                = "Detects an uncommon parent process of \"LINK.EXE\". Link.EXE in Microsoft incremental linker. Its a utility usually bundled with Visual Studio installation. Multiple utilities often found in the same folder (editbin.exe, dumpbin.exe, lib.exe, etc) have a hardcode call to the \"LINK.EXE\" binary without checking its validity. This would allow an attacker to sideload any binary with the name \"link.exe\" if one of the aforementioned tools get executed from a different location. By filtering the known locations of such utilities we can spot uncommon parent process of LINK.EXE that might be suspicious or malicious."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "LINK /" and FolderPath endswith "\\link.exe") and (not(((InitiatingProcessFolderPath contains "\\VC\\bin\\" or InitiatingProcessFolderPath contains "\\VC\\Tools\\") and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft Visual Studio\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft Visual Studio\\"))))
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
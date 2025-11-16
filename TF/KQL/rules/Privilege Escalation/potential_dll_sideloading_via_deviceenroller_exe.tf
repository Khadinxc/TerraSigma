resource "azurerm_sentinel_alert_rule_scheduled" "potential_dll_sideloading_via_deviceenroller_exe" {
  name                       = "potential_dll_sideloading_via_deviceenroller_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential DLL Sideloading Via DeviceEnroller.EXE"
  description                = "Detects the use of the PhoneDeepLink parameter to potentially sideload a DLL file that does not exist. This non-existent DLL file is named \"ShellChromeAPI.dll\". Adversaries can drop their own renamed DLL and execute it via DeviceEnroller.exe using this parameter"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "/PhoneDeepLink" and (FolderPath endswith "\\deviceenroller.exe" or ProcessVersionInfoOriginalFileName =~ "deviceenroller.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "DefenseEvasion"]
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
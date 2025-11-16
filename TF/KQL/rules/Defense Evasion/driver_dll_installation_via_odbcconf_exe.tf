resource "azurerm_sentinel_alert_rule_scheduled" "driver_dll_installation_via_odbcconf_exe" {
  name                       = "driver_dll_installation_via_odbcconf_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Driver/DLL Installation Via Odbcconf.EXE"
  description                = "Detects execution of \"odbcconf\" with \"INSTALLDRIVER\" which installs a new ODBC driver. Attackers abuse this to install and run malicious DLLs. - Legitimate driver DLLs being registered via \"odbcconf\" will generate false positives. Investigate the path of the DLL and its contents to determine if the action is authorized."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "INSTALLDRIVER " and ProcessCommandLine contains ".dll") and (FolderPath endswith "\\odbcconf.exe" or ProcessVersionInfoOriginalFileName =~ "odbcconf.exe")
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
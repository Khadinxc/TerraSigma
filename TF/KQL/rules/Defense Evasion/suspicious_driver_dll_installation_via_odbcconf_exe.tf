resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_driver_dll_installation_via_odbcconf_exe" {
  name                       = "suspicious_driver_dll_installation_via_odbcconf_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Driver/DLL Installation Via Odbcconf.EXE"
  description                = "Detects execution of \"odbcconf\" with the \"INSTALLDRIVER\" action where the driver doesn't contain a \".dll\" extension. This is often used as a defense evasion method. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "INSTALLDRIVER " and (FolderPath endswith "\\odbcconf.exe" or ProcessVersionInfoOriginalFileName =~ "odbcconf.exe")) and (not(ProcessCommandLine contains ".dll"))
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
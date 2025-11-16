resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_extension_shim_database_installation_via_sdbinst_exe" {
  name                       = "uncommon_extension_shim_database_installation_via_sdbinst_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Extension Shim Database Installation Via Sdbinst.EXE"
  description                = "Detects installation of a potentially suspicious new shim with an uncommon extension using sdbinst.exe. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\sdbinst.exe" or ProcessVersionInfoOriginalFileName =~ "sdbinst.exe") and (not((ProcessCommandLine =~ "" or ProcessCommandLine contains ".sdb" or ((ProcessCommandLine endswith " -c" or ProcessCommandLine endswith " -f" or ProcessCommandLine endswith " -mm" or ProcessCommandLine endswith " -t") or ProcessCommandLine contains " -m -bg") or isnull(ProcessCommandLine))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1546"]
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
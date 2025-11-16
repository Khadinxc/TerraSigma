resource "azurerm_sentinel_alert_rule_scheduled" "potential_binary_proxy_execution_via_cdb_exe" {
  name                       = "potential_binary_proxy_execution_via_cdb_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Binary Proxy Execution Via Cdb.EXE"
  description                = "Detects usage of \"cdb.exe\" to launch arbitrary processes or commands from a debugger script file - Legitimate use of debugging tools"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -c " or ProcessCommandLine contains " -cf ") and (FolderPath endswith "\\cdb.exe" or ProcessVersionInfoOriginalFileName =~ "CDB.Exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1106", "T1218", "T1127"]
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
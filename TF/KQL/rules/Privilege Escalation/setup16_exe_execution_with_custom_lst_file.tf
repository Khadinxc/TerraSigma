resource "azurerm_sentinel_alert_rule_scheduled" "setup16_exe_execution_with_custom_lst_file" {
  name                       = "setup16_exe_execution_with_custom_lst_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Setup16.EXE Execution With Custom .Lst File"
  description                = "Detects the execution of \"Setup16.EXE\" and old installation utility with a custom \".lst\" file. These \".lst\" file can contain references to external program that \"Setup16.EXE\" will execute. Attackers and adversaries might leverage this as a living of the land utility. - On modern Windows system, the \"Setup16\" utility is practically never used, hence false positive should be very rare."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessCommandLine contains " -m " and InitiatingProcessFolderPath =~ "C:\\Windows\\SysWOW64\\setup16.exe") and (not(FolderPath startswith "C:\\~MSSETUP.T\\"))
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
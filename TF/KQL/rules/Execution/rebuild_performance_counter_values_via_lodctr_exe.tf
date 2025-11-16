resource "azurerm_sentinel_alert_rule_scheduled" "rebuild_performance_counter_values_via_lodctr_exe" {
  name                       = "rebuild_performance_counter_values_via_lodctr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Rebuild Performance Counter Values Via Lodctr.EXE"
  description                = "Detects the execution of \"lodctr.exe\" to rebuild the performance counter registry values. This can be abused by attackers by providing a malicious config file to overwrite performance counter configuration to confuse and evade monitoring and security solutions. - Legitimate usage by an administrator"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -r" or ProcessCommandLine contains " /r" or ProcessCommandLine contains " –r" or ProcessCommandLine contains " —r" or ProcessCommandLine contains " ―r") and (FolderPath endswith "\\lodctr.exe" and ProcessVersionInfoOriginalFileName =~ "LODCTR.EXE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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
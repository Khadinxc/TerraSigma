resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_vmwaretoolboxcmd_exe_vm_state_change_script" {
  name                       = "potential_persistence_via_vmwaretoolboxcmd_exe_vm_state_change_script"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script"
  description                = "Detects execution of the \"VMwareToolBoxCmd.exe\" with the \"script\" and \"set\" flag to setup a specific script to run for a specific VM state"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " script " and ProcessCommandLine contains " set ") and (FolderPath endswith "\\VMwareToolBoxCmd.exe" or ProcessVersionInfoOriginalFileName =~ "toolbox-cmd.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Persistence"]
  techniques                 = ["T1059"]
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
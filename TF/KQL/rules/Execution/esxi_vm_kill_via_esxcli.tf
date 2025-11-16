resource "azurerm_sentinel_alert_rule_scheduled" "esxi_vm_kill_via_esxcli" {
  name                       = "esxi_vm_kill_via_esxcli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ESXi VM Kill Via ESXCLI"
  description                = "Detects execution of the \"esxcli\" command with the \"vm\" and \"kill\" flag in order to kill/shutdown a specific VM. - Legitimate administration activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "vm process" and ProcessCommandLine contains "kill") and FolderPath endswith "/esxcli"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Impact"]
  techniques                 = ["T1059", "T1529"]
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
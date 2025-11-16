resource "azurerm_sentinel_alert_rule_scheduled" "esxi_storage_information_discovery_via_esxcli" {
  name                       = "esxi_storage_information_discovery_via_esxcli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ESXi Storage Information Discovery Via ESXCLI"
  description                = "Detects execution of the \"esxcli\" command with the \"storage\" flag in order to retrieve information about the storage status and other related information. Seen used by malware such as DarkSide and LockBit. - Legitimate administration activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " get" or ProcessCommandLine contains " list") and (ProcessCommandLine contains "storage" and FolderPath endswith "/esxcli")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery", "Execution"]
  techniques                 = ["T1033", "T1007", "T1059"]
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
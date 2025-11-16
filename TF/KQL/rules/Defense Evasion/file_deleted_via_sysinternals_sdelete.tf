resource "azurerm_sentinel_alert_rule_scheduled" "file_deleted_via_sysinternals_sdelete" {
  name                       = "file_deleted_via_sysinternals_sdelete"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Deleted Via Sysinternals SDelete"
  description                = "Detects the deletion of files by the Sysinternals SDelete utility. It looks for the common name pattern used to rename files. - Legitimate usage"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith ".AAA" or FolderPath endswith ".ZZZ") and (not(FolderPath endswith "\\Wireshark\\radius\\dictionary.alcatel-lucent.aaa"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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
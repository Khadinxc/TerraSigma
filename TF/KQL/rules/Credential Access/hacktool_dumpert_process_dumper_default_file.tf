resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_dumpert_process_dumper_default_file" {
  name                       = "hacktool_dumpert_process_dumper_default_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Dumpert Process Dumper Default File"
  description                = "Detects the creation of the default dump file used by Outflank Dumpert tool. A process dumper, which dumps the lsass process memory - Very unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "dumpert.dmp"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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
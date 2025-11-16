resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_svchost_parent_process" {
  name                       = "uncommon_svchost_parent_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Svchost Parent Process"
  description                = "Detects an uncommon svchost parent process"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\svchost.exe" and (not(((InitiatingProcessFolderPath endswith "\\Mrt.exe" or InitiatingProcessFolderPath endswith "\\MsMpEng.exe" or InitiatingProcessFolderPath endswith "\\ngen.exe" or InitiatingProcessFolderPath endswith "\\rpcnet.exe" or InitiatingProcessFolderPath endswith "\\services.exe" or InitiatingProcessFolderPath endswith "\\TiWorker.exe") or (InitiatingProcessFolderPath in~ ("-", "")) or isnull(InitiatingProcessFolderPath))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "wfp_filter_added_via_registry" {
  name                       = "wfp_filter_added_via_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WFP Filter Added via Registry"
  description                = "Detects registry modifications that add Windows Filtering Platform (WFP) filters, which may be used to block security tools and EDR agents from reporting events."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\BFE\\Parameters\\Policy\\Persistent\\Filter*" and (not((InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\SysWOW64\\svchost.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1562", "T1569"]
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
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}
resource "azurerm_sentinel_alert_rule_scheduled" "dll_search_order_hijackig_via_additional_space_in_path" {
  name                       = "dll_search_order_hijackig_via_additional_space_in_path"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DLL Search Order Hijackig Via Additional Space in Path"
  description                = "Detects when an attacker create a similar folder structure to windows system folders such as (Windows, Program Files...) but with a space in order to trick DLL load search order and perform a \"DLL Search Order Hijacking\" attack"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ".dll" and (FolderPath startswith "C:\\Windows \\" or FolderPath startswith "C:\\Program Files \\" or FolderPath startswith "C:\\Program Files (x86) \\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation", "DefenseEvasion"]
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
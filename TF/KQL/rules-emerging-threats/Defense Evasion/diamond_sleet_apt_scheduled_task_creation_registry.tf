resource "azurerm_sentinel_alert_rule_scheduled" "diamond_sleet_apt_scheduled_task_creation_registry" {
  name                       = "diamond_sleet_apt_scheduled_task_creation_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Diamond Sleet APT Scheduled Task Creation - Registry"
  description                = "Detects registry event related to the creation of a scheduled task used by Diamond Sleet APT during exploitation of Team City CVE-2023-42793 vulnerability"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree*" and RegistryKey contains "Windows TeamCity Settings User Interface"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}
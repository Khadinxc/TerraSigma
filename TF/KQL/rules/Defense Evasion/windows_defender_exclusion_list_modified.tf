resource "azurerm_sentinel_alert_rule_scheduled" "windows_defender_exclusion_list_modified" {
  name                       = "windows_defender_exclusion_list_modified"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Defender Exclusion List Modified"
  description                = "Detects modifications to the Windows Defender exclusion registry key. This could indicate a potentially suspicious or even malicious activity by an attacker trying to add a new exclusion in order to bypass security. - Intended exclusions by administrators"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\Microsoft\\Windows Defender\\Exclusions*"
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
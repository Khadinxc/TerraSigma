resource "azurerm_sentinel_alert_rule_scheduled" "potential_credential_dumping_via_lsass_silentprocessexit_technique" {
  name                       = "potential_credential_dumping_via_lsass_silentprocessexit_technique"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Credential Dumping Via LSASS SilentProcessExit Technique"
  description                = "Detects changes to the Registry in which a monitor program gets registered to dump the memory of the lsass.exe process - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe"
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}
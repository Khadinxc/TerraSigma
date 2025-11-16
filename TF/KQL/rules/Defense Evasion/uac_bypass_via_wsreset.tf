resource "azurerm_sentinel_alert_rule_scheduled" "uac_bypass_via_wsreset" {
  name                       = "uac_bypass_via_wsreset"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Bypass Via Wsreset"
  description                = "Unfixed method for UAC bypass from Windows 10. WSReset.exe file associated with the Windows Store. It will run a binary file contained in a low-privilege registry."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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
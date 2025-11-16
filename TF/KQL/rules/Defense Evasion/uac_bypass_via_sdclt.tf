resource "azurerm_sentinel_alert_rule_scheduled" "uac_bypass_via_sdclt" {
  name                       = "uac_bypass_via_sdclt"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Bypass via Sdclt"
  description                = "Detects the pattern of UAC Bypass using registry key manipulation of sdclt.exe (e.g. UACMe 53)"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand" or (RegistryValueData matches regex "-1[0-9]{3}\\\\Software\\\\Classes\\\\" and RegistryKey endswith "Software\\Classes\\Folder\\shell\\open\\command\\SymbolicLinkValue")
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
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}
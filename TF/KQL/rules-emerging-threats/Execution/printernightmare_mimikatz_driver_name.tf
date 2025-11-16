resource "azurerm_sentinel_alert_rule_scheduled" "printernightmare_mimikatz_driver_name" {
  name                       = "printernightmare_mimikatz_driver_name"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PrinterNightmare Mimikatz Driver Name"
  description                = "Detects static QMS 810 and mimikatz driver name used by Mimikatz as exploited in CVE-2021-1675 and CVE-2021-34527 - Legitimate installation of printer driver QMS 810, Texas Instruments microLaser printer (unlikely)"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\Control\\Print\\Environments\\Windows x64\\Drivers\\Version-3\\QMS 810*" or RegistryKey contains "\\Control\\Print\\Environments\\Windows x64\\Drivers\\Version-3\\mimikatz") or (RegistryKey contains "legitprinter" and RegistryKey contains "\\Control\\Print\\Environments\\Windows") or ((RegistryKey contains "\\Control\\Print\\Environments" or RegistryKey contains "\\CurrentVersion\\Print\\Printers") and (RegistryKey contains "Gentil Kiwi" or RegistryKey contains "mimikatz printer" or RegistryKey contains "Kiwi Legit Printer"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1204"]
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
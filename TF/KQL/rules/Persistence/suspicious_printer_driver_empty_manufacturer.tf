resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_printer_driver_empty_manufacturer" {
  name                       = "suspicious_printer_driver_empty_manufacturer"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Printer Driver Empty Manufacturer"
  description                = "Detects a suspicious printer driver installation with an empty Manufacturer value - Alerts on legitimate printer drivers that do not set any more details in the Manufacturer value"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData =~ "(Empty)" and (RegistryKey contains "\\Control\\Print\\Environments\\Windows x64\\Drivers" and RegistryKey contains "\\Manufacturer")) and (not((RegistryKey endswith "\\CutePDF Writer v4.0*" or RegistryKey endswith "\\Version-3\\PDF24*" or (RegistryKey endswith "\\VNC Printer (PS)*" or RegistryKey endswith "\\VNC Printer (UD)*"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
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
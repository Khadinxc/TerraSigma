resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_odbc_driver_registered" {
  name                       = "potentially_suspicious_odbc_driver_registered"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious ODBC Driver Registered"
  description                = "Detects the registration of a new ODBC driver where the driver is located in a potentially suspicious location - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains ":\\PerfLogs\\" or RegistryValueData contains ":\\ProgramData\\" or RegistryValueData contains ":\\Temp\\" or RegistryValueData contains ":\\Users\\Public\\" or RegistryValueData contains ":\\Windows\\Registration\\CRMLog" or RegistryValueData contains ":\\Windows\\System32\\com\\dmp\\" or RegistryValueData contains ":\\Windows\\System32\\FxsTmp\\" or RegistryValueData contains ":\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\" or RegistryValueData contains ":\\Windows\\System32\\spool\\drivers\\color\\" or RegistryValueData contains ":\\Windows\\System32\\spool\\PRINTERS\\" or RegistryValueData contains ":\\Windows\\System32\\spool\\SERVERS\\" or RegistryValueData contains ":\\Windows\\System32\\Tasks_Migrated\\" or RegistryValueData contains ":\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\" or RegistryValueData contains ":\\Windows\\SysWOW64\\com\\dmp\\" or RegistryValueData contains ":\\Windows\\SysWOW64\\FxsTmp\\" or RegistryValueData contains ":\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\" or RegistryValueData contains ":\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\" or RegistryValueData contains ":\\Windows\\Tasks\\" or RegistryValueData contains ":\\Windows\\Temp\\" or RegistryValueData contains ":\\Windows\\Tracing\\" or RegistryValueData contains "\\AppData\\Local\\Temp\\" or RegistryValueData contains "\\AppData\\Roaming\\") and RegistryKey endswith "\\SOFTWARE\\ODBC\\ODBCINST.INI*" and (RegistryKey endswith "\\Driver" or RegistryKey endswith "\\Setup")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess", "Persistence"]
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
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}
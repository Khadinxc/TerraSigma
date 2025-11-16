resource "azurerm_sentinel_alert_rule_scheduled" "new_odbc_driver_registered" {
  name                       = "new_odbc_driver_registered"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New ODBC Driver Registered"
  description                = "Detects the registration of a new ODBC driver. - Likely"
  severity                   = "Low"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\SOFTWARE\\ODBC\\ODBCINST.INI*" and RegistryKey endswith "\\Driver") and (not((RegistryValueData =~ "%WINDIR%\\System32\\SQLSRV32.dll" and RegistryKey endswith "\\SQL Server*"))) and (not(((RegistryValueData endswith "\\ACEODBC.DLL" and RegistryValueData startswith "C:\\Progra" and RegistryKey contains "\\Microsoft Access ") or (RegistryValueData endswith "\\ACEODBC.DLL" and RegistryValueData startswith "C:\\Progra" and RegistryKey contains "\\Microsoft Excel Driver"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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
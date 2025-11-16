resource "azurerm_sentinel_alert_rule_scheduled" "python_function_execution_security_warning_disabled_in_excel_registry" {
  name                       = "python_function_execution_security_warning_disabled_in_excel_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Python Function Execution Security Warning Disabled In Excel - Registry"
  description                = "Detects changes to the registry value \"PythonFunctionWarnings\" that would prevent any warnings or alerts from showing when Python functions are about to be executed. Threat actors could run malicious code through the new Microsoft Excel feature that allows Python to run within the spreadsheet."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000001)" and RegistryKey endswith "\\Microsoft\\Office*" and RegistryKey endswith "\\Excel\\Security\\PythonFunctionWarnings"
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
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}
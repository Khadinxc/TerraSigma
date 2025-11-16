resource "azurerm_sentinel_alert_rule_scheduled" "python_function_execution_security_warning_disabled_in_excel" {
  name                       = "python_function_execution_security_warning_disabled_in_excel"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Python Function Execution Security Warning Disabled In Excel"
  description                = "Detects changes to the registry value \"PythonFunctionWarnings\" that would prevent any warnings or alerts from showing when Python functions are about to be executed. Threat actors could run malicious code through the new Microsoft Excel feature that allows Python to run within the spreadsheet."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " 0" and (ProcessCommandLine contains "\\Microsoft\\Office\\" and ProcessCommandLine contains "\\Excel\\Security" and ProcessCommandLine contains "PythonFunctionWarnings")
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}
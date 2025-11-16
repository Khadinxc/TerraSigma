resource "azurerm_sentinel_alert_rule_scheduled" "potential_powershell_execution_policy_tampering" {
  name                       = "potential_powershell_execution_policy_tampering"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential PowerShell Execution Policy Tampering"
  description                = "Detects changes to the PowerShell execution policy in order to bypass signing requirements for script execution"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryValueData contains "Bypass" or RegistryValueData contains "Unrestricted") and (RegistryKey endswith "\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy" or RegistryKey endswith "\\Policies\\Microsoft\\Windows\\PowerShell\\ExecutionPolicy")) and (not((InitiatingProcessFolderPath contains ":\\Windows\\System32\\" or InitiatingProcessFolderPath contains ":\\Windows\\SysWOW64\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
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
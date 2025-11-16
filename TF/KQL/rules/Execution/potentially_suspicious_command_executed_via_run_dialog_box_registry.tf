resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_command_executed_via_run_dialog_box_registry" {
  name                       = "potentially_suspicious_command_executed_via_run_dialog_box_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Command Executed Via Run Dialog Box - Registry"
  description                = "Detects execution of commands via the run dialog box on Windows by checking values of the \"RunMRU\" registry key. This technique was seen being abused by threat actors to deceive users into pasting and executing malicious commands, often disguised as CAPTCHA verification steps."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" and (((RegistryValueData contains "powershell" or RegistryValueData contains "pwsh") and (RegistryValueData contains " -e " or RegistryValueData contains " -ec " or RegistryValueData contains " -en " or RegistryValueData contains " -enc " or RegistryValueData contains " -enco" or RegistryValueData contains "ftp" or RegistryValueData contains "Hidden" or RegistryValueData contains "http" or RegistryValueData contains "iex" or RegistryValueData contains "Invoke-")) or (RegistryValueData contains "wmic" and (RegistryValueData contains "shadowcopy" or RegistryValueData contains "process call create")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
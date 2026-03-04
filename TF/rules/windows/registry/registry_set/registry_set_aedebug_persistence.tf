resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_aedebug_persistence" {
  name                       = "registry_set_aedebug_persistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Add Debugger Entry To AeDebug For Persistence"
  description                = "Detects when an attacker adds a new \"Debugger\" value to the \"AeDebug\" key in order to achieve persistence which will get invoked when an application crashes Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_aedebug_persistence.yml - Legitimate use of the key to setup a debugger. Which is often the case on developers machines | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_aedebug_persistence.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData endswith ".dll" and RegistryKey contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\Debugger") and (not(RegistryValueData =~ "\"C:\\WINDOWS\\system32\\vsjitdebugger.exe\" -p %ld -e %ld -j 0x%p"))
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}
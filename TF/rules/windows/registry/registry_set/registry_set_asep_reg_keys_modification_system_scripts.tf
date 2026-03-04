resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_asep_reg_keys_modification_system_scripts" {
  name                       = "registry_set_asep_reg_keys_modification_system_scripts"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Scripts Autorun Keys Modification"
  description                = "Detects modification of autostart extensibility point (ASEP) in registry. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_system_scripts.yml - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason - Legitimate administrator sets up autorun keys for legitimate reason | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_system_scripts.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\Software\\Policies\\Microsoft\\Windows\\System\\Scripts" and (RegistryKey contains "\\Startup" or RegistryKey contains "\\Shutdown" or RegistryKey contains "\\Logon" or RegistryKey contains "\\Logoff") and (not(RegistryValueData =~ "(Empty)"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_rpcrt4_etw_tamper" {
  name                       = "registry_set_rpcrt4_etw_tamper"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ETW Logging Disabled For rpcrt4.dll"
  description                = "Detects changes to the \"ExtErrorInformation\" key in order to disable ETW logging for rpcrt4.dll Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_rpcrt4_etw_tamper.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_rpcrt4_etw_tamper.yml"
  severity                   = "Low"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData in~ ("DWORD (0x00000000)", "DWORD (0x00000002)")) and RegistryKey endswith "\\Microsoft\\Windows NT\\Rpc\\ExtErrorInformation"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112", "T1562"]
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
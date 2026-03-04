resource "azurerm_sentinel_alert_rule_scheduled" "registry_delete_mstsc_history_cleared" {
  name                       = "registry_delete_mstsc_history_cleared"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Terminal Server Client Connection History Cleared - Registry"
  description                = "Detects the deletion of registry keys containing the MSTSC connection history Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_mstsc_history_cleared.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_mstsc_history_cleared.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (ActionType =~ "DeleteValue" and RegistryKey contains "\\Microsoft\\Terminal Server Client\\Default\\MRU") or ((ActionType in~ ("RegistryKeyDeleted", "RegistryValueDeleted")) and RegistryKey endswith "\\Microsoft\\Terminal Server Client\\Servers*")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1070", "T1112"]
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
}
resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_persistence_typed_paths" {
  name                       = "registry_set_persistence_typed_paths"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via TypedPaths"
  description                = "Detects modification addition to the 'TypedPaths' key in the user or admin registry from a non standard application. Which might indicate persistence attempt Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_persistence_typed_paths.yml - Unlikely | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_persistence_typed_paths.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths*" and (not((InitiatingProcessFolderPath in~ ("C:\\Windows\\explorer.exe", "C:\\Windows\\SysWOW64\\explorer.exe"))))
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
}
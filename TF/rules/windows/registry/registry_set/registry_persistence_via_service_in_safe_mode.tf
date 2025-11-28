resource "azurerm_sentinel_alert_rule_scheduled" "registry_persistence_via_service_in_safe_mode" {
  name                       = "registry_persistence_via_service_in_safe_mode"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Persistence via Service in Safe Mode"
  description                = "Detects the modification of the registry to allow a driver or service to persist in Safe Mode."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData =~ "Service" and (RegistryKey endswith "\\Control\\SafeBoot\\Minimal*" or RegistryKey endswith "\\Control\\SafeBoot\\Network*") and RegistryKey endswith "\\(Default)") and (not(((RegistryValueData =~ "Service" and InitiatingProcessFolderPath =~ "C:\\Hexnode\\Hexnode Agent\\Current\\HexnodeAgent.exe" and (RegistryKey endswith "\\Control\\SafeBoot\\Minimal\\Hexnode Updater\\(Default)" or RegistryKey endswith "\\Control\\SafeBoot\\Network\\Hexnode Updater\\(Default)" or RegistryKey endswith "\\Control\\SafeBoot\\Minimal\\Hexnode Agent\\(Default)" or RegistryKey endswith "\\Control\\SafeBoot\\Network\\Hexnode Agent\\(Default)")) or (RegistryValueData =~ "Service" and InitiatingProcessFolderPath endswith "\\MBAMInstallerService.exe" and RegistryKey endswith "\\MBAMService\\(Default)") or (InitiatingProcessFolderPath =~ "C:\\WINDOWS\\system32\\msiexec.exe" and (RegistryKey endswith "\\Control\\SafeBoot\\Minimal\\SAVService\\(Default)" or RegistryKey endswith "\\Control\\SafeBoot\\Network\\SAVService\\(Default)")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1564"]
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
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
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
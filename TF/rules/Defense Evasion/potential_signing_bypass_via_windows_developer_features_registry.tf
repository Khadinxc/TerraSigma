resource "azurerm_sentinel_alert_rule_scheduled" "potential_signing_bypass_via_windows_developer_features_registry" {
  name                       = "potential_signing_bypass_via_windows_developer_features_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Signing Bypass Via Windows Developer Features - Registry"
  description                = "Detects when the enablement of developer features such as \"Developer Mode\" or \"Application Sideloading\". Which allows the user to install untrusted packages."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000001)" and (RegistryKey contains "\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock" or RegistryKey endswith "\\Policies\\Microsoft\\Windows\\Appx*") and (RegistryKey endswith "\\AllowAllTrustedApps" or RegistryKey endswith "\\AllowDevelopmentWithoutDevLicense")
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
resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_environment_variable_has_been_registered" {
  name                       = "suspicious_environment_variable_has_been_registered"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Environment Variable Has Been Registered"
  description                = "Detects the creation of user-specific or system-wide environment variables via the registry. Which contains suspicious commands and strings"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryValueData in~ ("powershell", "pwsh")) or (RegistryValueData contains "\\AppData\\Local\\Temp\\" or RegistryValueData contains "C:\\Users\\Public\\" or RegistryValueData contains "TVqQAAMAAAAEAAAA" or RegistryValueData contains "TVpQAAIAAAAEAA8A" or RegistryValueData contains "TVqAAAEAAAAEABAA" or RegistryValueData contains "TVoAAAAAAAAAAAAA" or RegistryValueData contains "TVpTAQEAAAAEAAAA" or RegistryValueData contains "SW52b2tlL" or RegistryValueData contains "ludm9rZS" or RegistryValueData contains "JbnZva2Ut" or RegistryValueData contains "SQBuAHYAbwBrAGUALQ" or RegistryValueData contains "kAbgB2AG8AawBlAC0A" or RegistryValueData contains "JAG4AdgBvAGsAZQAtA") or (RegistryValueData startswith "SUVY" or RegistryValueData startswith "SQBFAF" or RegistryValueData startswith "SQBuAH" or RegistryValueData startswith "cwBhA" or RegistryValueData startswith "aWV4" or RegistryValueData startswith "aQBlA" or RegistryValueData startswith "R2V0" or RegistryValueData startswith "dmFy" or RegistryValueData startswith "dgBhA" or RegistryValueData startswith "dXNpbm" or RegistryValueData startswith "H4sIA" or RegistryValueData startswith "Y21k" or RegistryValueData startswith "cABhAH" or RegistryValueData startswith "Qzpc" or RegistryValueData startswith "Yzpc")) and RegistryKey endswith "\\Environment*"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence"]
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
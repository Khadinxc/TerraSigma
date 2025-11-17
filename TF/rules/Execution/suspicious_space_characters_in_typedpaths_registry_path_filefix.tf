resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_space_characters_in_typedpaths_registry_path_filefix" {
  name                       = "suspicious_space_characters_in_typedpaths_registry_path_filefix"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Space Characters in TypedPaths Registry Path - FileFix"
  description                = "Detects the occurrence of numerous space characters in TypedPaths registry paths, which may indicate execution via phishing lures using file-fix techniques to hide malicious commands. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains "#" and RegistryKey endswith "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\\url1") and (RegistryValueData contains "            " or RegistryValueData contains "            " or RegistryValueData contains "            " or RegistryValueData contains "            " or RegistryValueData contains "            " or RegistryValueData contains "            " or RegistryValueData contains "            " or RegistryValueData contains "            " or RegistryValueData contains "            " or RegistryValueData contains "            " or RegistryValueData contains "            " or RegistryValueData contains "            " or RegistryValueData contains "            ")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1204", "T1027"]
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
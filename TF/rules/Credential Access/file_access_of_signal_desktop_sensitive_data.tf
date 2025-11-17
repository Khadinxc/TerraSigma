resource "azurerm_sentinel_alert_rule_scheduled" "file_access_of_signal_desktop_sensitive_data" {
  name                       = "file_access_of_signal_desktop_sensitive_data"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Access Of Signal Desktop Sensitive Data"
  description                = "Detects access to Signal Desktop's sensitive data files: db.sqlite and config.json. The db.sqlite file in Signal Desktop stores all locally saved messages in an encrypted SQLite database, while the config.json contains the decryption key needed to access that data. Since the key is stored in plain text, a threat actor who gains access to both files can decrypt and read sensitive messages without needing the users credentials. Currently the rule only covers the default Signal installation path in AppData\\Roaming. Signal Portable installations may use different paths based on user configuration. Additional paths can be added to the selection as needed. - Unlikely, but possible from AV or backup software accessing the files."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\AppData\\Roaming\\Signal*" and (RegistryKey endswith "\\config.json" or RegistryKey endswith "\\db.sqlite")) and (not((InitiatingProcessFolderPath endswith "\\signal-portable.exe" or InitiatingProcessFolderPath endswith "\\signal.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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
}
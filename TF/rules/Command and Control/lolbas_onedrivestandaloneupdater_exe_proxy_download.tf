resource "azurerm_sentinel_alert_rule_scheduled" "lolbas_onedrivestandaloneupdater_exe_proxy_download" {
  name                       = "lolbas_onedrivestandaloneupdater_exe_proxy_download"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Lolbas OneDriveStandaloneUpdater.exe Proxy Download"
  description                = "Detects setting a custom URL for OneDriveStandaloneUpdater.exe to download a file from the Internet without executing any anomalous executables with suspicious arguments. The downloaded file will be in C:\\Users\\redacted\\AppData\\Local\\Microsoft\\OneDrive\\StandaloneUpdaterreSignInSettingsConfig.json"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\SOFTWARE\\Microsoft\\OneDrive\\UpdateOfficeConfig\\UpdateRingSettingURLFromOC"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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
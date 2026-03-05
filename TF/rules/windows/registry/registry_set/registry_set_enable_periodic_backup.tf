resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_enable_periodic_backup" {
  name                       = "registry_set_enable_periodic_backup"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Periodic Backup For System Registry Hives Enabled"
  description                = <<DESC
    Detects the enabling of the "EnablePeriodicBackup" registry value. Once enabled, The OS will backup System registry hives on restarts to the "C:\Windows\System32\config\RegBack" folder. Windows creates a "RegIdleBackup" task to manage subsequent backups. Registry backup was a default behavior on Windows and was disabled as of "Windows 10, version 1803".

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_enable_periodic_backup.yml

    False Positives:
    - Legitimate need for RegBack feature by administrators.
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000001)" and RegistryKey endswith "\\Control\\Session Manager\\Configuration Manager\\EnablePeriodicBackup"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1113"]
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
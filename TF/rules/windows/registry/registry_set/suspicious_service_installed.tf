resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_service_installed" {
  name                       = "suspicious_service_installed"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Service Installed"
  description                = "Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders. Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU) - Other legimate tools using this service names and drivers. Note - clever attackers may easily bypass this detection by just renaming the services. Therefore just Medium-level and don't rely on it."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey in~ ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001\\Services\\NalDrv\\ImagePath", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001\\Services\\PROCEXP152\\ImagePath")) and (not((RegistryValueData contains "\\WINDOWS\\system32\\Drivers\\PROCEXP152.SYS" and (InitiatingProcessFolderPath endswith "\\procexp64.exe" or InitiatingProcessFolderPath endswith "\\procexp.exe" or InitiatingProcessFolderPath endswith "\\procmon64.exe" or InitiatingProcessFolderPath endswith "\\procmon.exe" or InitiatingProcessFolderPath endswith "\\handle.exe" or InitiatingProcessFolderPath endswith "\\handle64.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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
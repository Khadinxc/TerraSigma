resource "azurerm_sentinel_alert_rule_scheduled" "winsock2_autorun_keys_modification" {
  name                       = "winsock2_autorun_keys_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WinSock2 Autorun Keys Modification"
  description                = "Detects modification of autostart extensibility point (ASEP) in registry. - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason - Legitimate administrator sets up autorun keys for legitimate reason"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters" and (RegistryKey contains "\\Protocol_Catalog9\\Catalog_Entries" or RegistryKey contains "\\NameSpace_Catalog5\\Catalog_Entries") and (not((RegistryValueData =~ "(Empty)" or InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\MsiExec.exe" or InitiatingProcessFolderPath =~ "C:\\Windows\\syswow64\\MsiExec.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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
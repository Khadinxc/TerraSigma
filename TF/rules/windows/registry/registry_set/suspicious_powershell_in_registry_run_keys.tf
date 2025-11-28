resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_powershell_in_registry_run_keys" {
  name                       = "suspicious_powershell_in_registry_run_keys"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious PowerShell In Registry Run Keys"
  description                = "Detects potential PowerShell commands or code within registry run keys - Legitimate admin or third party scripts. Baseline according to your environment"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains "powershell" or RegistryValueData contains "pwsh " or RegistryValueData contains "FromBase64String" or RegistryValueData contains ".DownloadFile(" or RegistryValueData contains ".DownloadString(" or RegistryValueData contains " -w hidden " or RegistryValueData contains " -w 1 " or RegistryValueData contains "-windowstyle hidden" or RegistryValueData contains "-window hidden" or RegistryValueData contains " -nop " or RegistryValueData contains " -encodedcommand " or RegistryValueData contains "-ExecutionPolicy Bypass" or RegistryValueData contains "Invoke-Expression" or RegistryValueData contains "IEX (" or RegistryValueData contains "Invoke-Command" or RegistryValueData contains "ICM -" or RegistryValueData contains "Invoke-WebRequest" or RegistryValueData contains "IWR " or RegistryValueData contains "Invoke-RestMethod" or RegistryValueData contains "IRM " or RegistryValueData contains " -noni " or RegistryValueData contains " -noninteractive ") and (RegistryKey contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" or RegistryKey contains "\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" or RegistryKey contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run")
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
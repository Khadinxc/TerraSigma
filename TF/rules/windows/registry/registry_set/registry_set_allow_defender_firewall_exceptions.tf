resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_allow_defender_firewall_exceptions" {
  name                       = "registry_set_allow_defender_firewall_exceptions"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Allow Exceptions in Microsoft Defender Firewall via Registry"
  description                = <<DESC
    Detects the degradation of the system firewall security by the DoNotAllowExceptions policy value being set to 0 (DWORD 0x00000000), which re-enables application and port exceptions in the Microsoft Defender Firewall and can restore network paths that a hardened profile would block.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_allow_defender_firewall_exceptions.yml
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData =~ "DWORD (0x00000000)" and RegistryKey endswith "\\Services\\SharedAccess\\Parameters\\FirewallPolicy*" and RegistryKey endswith "\\DoNotAllowExceptions") and (not((InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\SysWOW64\\svchost.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  techniques                 = ["T1686"]
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
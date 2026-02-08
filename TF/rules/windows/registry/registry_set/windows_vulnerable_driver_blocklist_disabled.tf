resource "azurerm_sentinel_alert_rule_scheduled" "windows_vulnerable_driver_blocklist_disabled" {
  name                       = "windows_vulnerable_driver_blocklist_disabled"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Vulnerable Driver Blocklist Disabled"
  description                = "Detects when the Windows Vulnerable Driver Blocklist is set to disabled. This setting is crucial for preventing the loading of known vulnerable drivers, and its modification may indicate an attempt to bypass security controls. It is often targeted by threat actors to facilitate the installation of malicious or vulnerable drivers, particularly in scenarios involving Endpoint Detection and Response (EDR) bypass techniques. This rule applies to systems that support the Vulnerable Driver Blocklist feature, including Windows 10 version 1903 and later, and Windows Server 2022 and later. Note that this change will require a reboot to take effect, and this rule only detects the registry modification action. - Unlikely and should be investigated immediately."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000000)" and RegistryKey endswith "\\Control\\CI\\Config\\VulnerableDriverBlocklistEnable"
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
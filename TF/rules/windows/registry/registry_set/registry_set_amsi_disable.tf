resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_amsi_disable" {
  name                       = "registry_set_amsi_disable"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "AMSI Disabled via Registry Modification"
  description                = "Detects attempts to disable AMSI (Anti-Malware Scan Interface) by modifying the AmsiEnable registry value. Anti-Malware Scan Interface (AMSI) is a security feature in Windows that allows applications and services to integrate with anti-malware products for enhanced protection against malicious content. Adversaries may attempt to disable AMSI to evade detection by security software, allowing them to execute malicious scripts or code without being scanned. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_amsi_disable.yml - Unlikely | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_amsi_disable.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000000)" and RegistryKey endswith "\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable"
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
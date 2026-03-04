resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_dns_over_https_enabled" {
  name                       = "registry_set_dns_over_https_enabled"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DNS-over-HTTPS Enabled by Registry"
  description                = "Detects when a user enables DNS-over-HTTPS. This can be used to hide internet activity or be used to hide the process of exfiltrating data. With this enabled organization will lose visibility into data such as query type, response and originating IP that are used to determine bad actors. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_dns_over_https_enabled.yml - Unlikely | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_dns_over_https_enabled.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData =~ "secure" and RegistryKey endswith "\\SOFTWARE\\Google\\Chrome\\DnsOverHttpsMode") or (RegistryValueData =~ "DWORD (0x00000001)" and RegistryKey endswith "\\SOFTWARE\\Policies\\Microsoft\\Edge\\BuiltInDnsClientEnabled") or (RegistryValueData =~ "DWORD (0x00000001)" and RegistryKey endswith "\\SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS\\Enabled")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1140", "T1112"]
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
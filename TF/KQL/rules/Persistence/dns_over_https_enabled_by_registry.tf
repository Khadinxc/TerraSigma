resource "azurerm_sentinel_alert_rule_scheduled" "dns_over_https_enabled_by_registry" {
  name                       = "dns_over_https_enabled_by_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DNS-over-HTTPS Enabled by Registry"
  description                = "Detects when a user enables DNS-over-HTTPS. This can be used to hide internet activity or be used to hide the process of exfiltrating data. With this enabled organization will lose visibility into data such as query type, response and originating IP that are used to determine bad actors. - Unlikely"
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}
resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_persistence_outlook_homepage" {
  name                       = "registry_set_persistence_outlook_homepage"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Outlook Home Page"
  description                = "Detects potential persistence activity via outlook home page. An attacker can set a home page to achieve code execution and persistence by editing the WebView registry keys. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_persistence_outlook_homepage.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_persistence_outlook_homepage.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\Software\\Microsoft\\Office*" and RegistryKey endswith "\\Outlook\\WebView*") and RegistryKey endswith "\\URL"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence"]
  techniques                 = ["T1112"]
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
}
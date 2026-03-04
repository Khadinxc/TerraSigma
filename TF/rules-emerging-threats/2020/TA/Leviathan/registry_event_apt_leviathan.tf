resource "azurerm_sentinel_alert_rule_scheduled" "registry_event_apt_leviathan" {
  name                       = "registry_event_apt_leviathan"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Leviathan Registry Key Activity"
  description                = "Detects registry key used by Leviathan APT in Malaysian focused campaign Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2020/TA/Leviathan/registry_event_apt_leviathan.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2020/TA/Leviathan/registry_event_apt_leviathan.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ntkd"
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
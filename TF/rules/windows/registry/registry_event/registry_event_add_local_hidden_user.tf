resource "azurerm_sentinel_alert_rule_scheduled" "registry_event_add_local_hidden_user" {
  name                       = "registry_event_add_local_hidden_user"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Creation of a Local Hidden User Account by Registry"
  description                = "Sysmon registry detection of a local hidden user account. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_event/registry_event_add_local_hidden_user.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_event/registry_event_add_local_hidden_user.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where InitiatingProcessFolderPath endswith "\\lsass.exe" and RegistryKey endswith "\\SAM\\SAM\\Domains\\Account\\Users\\Names*" and RegistryKey endswith "$\\(Default)"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1136"]
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
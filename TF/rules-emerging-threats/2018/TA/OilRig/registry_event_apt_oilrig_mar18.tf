resource "azurerm_sentinel_alert_rule_scheduled" "registry_event_apt_oilrig_mar18" {
  name                       = "registry_event_apt_oilrig_mar18"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "OilRig APT Registry Persistence"
  description                = <<DESC
    Detects OilRig registry persistence as reported by Nyotron in their March 2018 report

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2018/TA/OilRig/registry_event_apt_oilrig_mar18.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UMe" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UT"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence", "DefenseEvasion", "CommandAndControl"]
  techniques                 = ["T1053", "T1543", "T1112", "T1071"]
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
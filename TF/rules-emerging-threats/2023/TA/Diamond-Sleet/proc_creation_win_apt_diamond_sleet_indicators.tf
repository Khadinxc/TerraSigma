resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_apt_diamond_sleet_indicators" {
  name                       = "proc_creation_win_apt_diamond_sleet_indicators"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Diamond Sleet APT Process Activity Indicators"
  description                = <<DESC
    Detects process creation activity indicators related to Diamond Sleet APT

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2023/TA/Diamond-Sleet/proc_creation_win_apt_diamond_sleet_indicators.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " uTYNkfKxHiZrx3KJ"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}
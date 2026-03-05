resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_apt_evilnum_jul20" {
  name                       = "proc_creation_win_apt_evilnum_jul20"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "EvilNum APT Golden Chickens Deployment Via OCX Files"
  description                = <<DESC
    Detects Golden Chickens deployment method as used by Evilnum and described in ESET July 2020 report

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2020/TA/Evilnum/proc_creation_win_apt_evilnum_jul20.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "regsvr32" and ProcessCommandLine contains "/s" and ProcessCommandLine contains "/i" and ProcessCommandLine contains "\\AppData\\Roaming\\" and ProcessCommandLine contains ".ocx"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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
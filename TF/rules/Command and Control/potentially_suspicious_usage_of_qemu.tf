resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_usage_of_qemu" {
  name                       = "potentially_suspicious_usage_of_qemu"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Usage Of Qemu"
  description                = "Detects potentially suspicious execution of the Qemu utility in a Windows environment. Threat actors have leveraged this utility and this technique for achieving network access as reported by Kaspersky."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "-m 1M" or ProcessCommandLine contains "-m 2M" or ProcessCommandLine contains "-m 3M") and (ProcessCommandLine contains "restrict=off" and ProcessCommandLine contains "-netdev " and ProcessCommandLine contains "connect=" and ProcessCommandLine contains "-nographic")) and (not((ProcessCommandLine contains " -cdrom " or ProcessCommandLine contains " type=virt " or ProcessCommandLine contains " -blockdev ")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1090", "T1572"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}
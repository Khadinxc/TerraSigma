resource "azurerm_sentinel_alert_rule_scheduled" "apt31_judgement_panda_activity" {
  name                       = "apt31_judgement_panda_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "APT31 Judgement Panda Activity"
  description                = "Detects APT31 Judgement Panda activity as described in the Crowdstrike 2019 Global Threat Report - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "\\aaaa\\procdump64.exe" or ProcessCommandLine contains "\\aaaa\\netsess.exe" or ProcessCommandLine contains "\\aaaa\\7za.exe" or ProcessCommandLine contains "\\c$\\aaaa\\") and (ProcessCommandLine contains "copy \\\\" and ProcessCommandLine contains "c$")) or (ProcessCommandLine contains "ldifde" and ProcessCommandLine contains "-f -n" and ProcessCommandLine contains "eprod.ldf")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection", "LateralMovement", "CredentialAccess"]
  techniques                 = ["T1003", "T1560"]
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
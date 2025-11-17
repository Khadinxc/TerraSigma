resource "azurerm_sentinel_alert_rule_scheduled" "potential_execution_of_sysinternals_tools" {
  name                       = "potential_execution_of_sysinternals_tools"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Execution of Sysinternals Tools"
  description                = "Detects command lines that contain the 'accepteula' flag which could be a sign of execution of one of the Sysinternals tools - Legitimate use of SysInternals tools - Programs that use the same command line flag"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " -accepteula" or ProcessCommandLine contains " /accepteula" or ProcessCommandLine contains " –accepteula" or ProcessCommandLine contains " —accepteula" or ProcessCommandLine contains " ―accepteula"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1588"]
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
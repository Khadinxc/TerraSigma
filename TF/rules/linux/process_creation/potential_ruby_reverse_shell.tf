resource "azurerm_sentinel_alert_rule_scheduled" "potential_ruby_reverse_shell" {
  name                       = "potential_ruby_reverse_shell"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Ruby Reverse Shell"
  description                = "Detects execution of ruby with the \"-e\" flag and calls to \"socket\" related functions. This could be an indication of a potential attempt to setup a reverse shell"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " ash" or ProcessCommandLine contains " bash" or ProcessCommandLine contains " bsh" or ProcessCommandLine contains " csh" or ProcessCommandLine contains " ksh" or ProcessCommandLine contains " pdksh" or ProcessCommandLine contains " sh" or ProcessCommandLine contains " tcsh") and (ProcessCommandLine contains " -e" and ProcessCommandLine contains "rsocket" and ProcessCommandLine contains "TCPSocket") and FolderPath contains "ruby"
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

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
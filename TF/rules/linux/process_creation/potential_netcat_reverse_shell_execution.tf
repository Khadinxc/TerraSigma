resource "azurerm_sentinel_alert_rule_scheduled" "potential_netcat_reverse_shell_execution" {
  name                       = "potential_netcat_reverse_shell_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Netcat Reverse Shell Execution"
  description                = "Detects execution of netcat with the \"-e\" flag followed by common shells. This could be a sign of a potential reverse shell setup. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -c " or ProcessCommandLine contains " -e ") and (FolderPath endswith "/nc" or FolderPath endswith "/ncat") and (ProcessCommandLine contains " ash" or ProcessCommandLine contains " bash" or ProcessCommandLine contains " bsh" or ProcessCommandLine contains " csh" or ProcessCommandLine contains " ksh" or ProcessCommandLine contains " pdksh" or ProcessCommandLine contains " sh" or ProcessCommandLine contains " tcsh" or ProcessCommandLine contains "/bin/ash" or ProcessCommandLine contains "/bin/bash" or ProcessCommandLine contains "/bin/bsh" or ProcessCommandLine contains "/bin/csh" or ProcessCommandLine contains "/bin/ksh" or ProcessCommandLine contains "/bin/pdksh" or ProcessCommandLine contains "/bin/sh" or ProcessCommandLine contains "/bin/tcsh" or ProcessCommandLine contains "/bin/zsh" or ProcessCommandLine contains "$IFSash" or ProcessCommandLine contains "$IFSbash" or ProcessCommandLine contains "$IFSbsh" or ProcessCommandLine contains "$IFScsh" or ProcessCommandLine contains "$IFSksh" or ProcessCommandLine contains "$IFSpdksh" or ProcessCommandLine contains "$IFSsh" or ProcessCommandLine contains "$IFStcsh" or ProcessCommandLine contains "$IFSzsh")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
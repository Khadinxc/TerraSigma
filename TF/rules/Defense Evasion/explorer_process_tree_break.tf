resource "azurerm_sentinel_alert_rule_scheduled" "explorer_process_tree_break" {
  name                       = "explorer_process_tree_break"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Explorer Process Tree Break"
  description                = "Detects a command line process that uses explorer.exe to launch arbitrary commands or binaries, which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer spawning from \"svchost\""
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}" or (ProcessCommandLine contains "explorer.exe" and (ProcessCommandLine contains " -root," or ProcessCommandLine contains " /root," or ProcessCommandLine contains " –root," or ProcessCommandLine contains " —root," or ProcessCommandLine contains " ―root,"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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
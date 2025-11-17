resource "azurerm_sentinel_alert_rule_scheduled" "potential_commandline_path_traversal_via_cmd_exe" {
  name                       = "potential_commandline_path_traversal_via_cmd_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential CommandLine Path Traversal Via Cmd.EXE"
  description                = "Detects potential path traversal attempt via cmd.exe. Could indicate possible command/argument confusion/hijacking - Java tools are known to produce false-positive when loading libraries"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((InitiatingProcessCommandLine contains "/c" or InitiatingProcessCommandLine contains "/k" or InitiatingProcessCommandLine contains "/r") or (ProcessCommandLine contains "/c" or ProcessCommandLine contains "/k" or ProcessCommandLine contains "/r")) and (InitiatingProcessFolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cmd.exe" or ProcessVersionInfoOriginalFileName =~ "cmd.exe") and (InitiatingProcessCommandLine =~ "/../../" or ProcessCommandLine contains "/../../")) and (not(ProcessCommandLine contains "\\Tasktop\\keycloak\\bin\\/../../jre\\bin\\java"))
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
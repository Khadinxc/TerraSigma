resource "azurerm_sentinel_alert_rule_scheduled" "forfiles_exe_child_process_masquerading" {
  name                       = "forfiles_exe_child_process_masquerading"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Forfiles.EXE Child Process Masquerading"
  description                = "Detects the execution of \"forfiles\" from a non-default location, in order to potentially spawn a custom \"cmd.exe\" from the current working directory."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine startswith "/c echo \"" and FolderPath endswith "\\cmd.exe" and (InitiatingProcessCommandLine endswith ".exe" or InitiatingProcessCommandLine endswith ".exe\"")) and (not(((FolderPath contains ":\\Windows\\System32\\" or FolderPath contains ":\\Windows\\SysWOW64\\") and FolderPath endswith "\\cmd.exe" and (InitiatingProcessFolderPath contains ":\\Windows\\System32\\" or InitiatingProcessFolderPath contains ":\\Windows\\SysWOW64\\") and InitiatingProcessFolderPath endswith "\\forfiles.exe")))
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

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
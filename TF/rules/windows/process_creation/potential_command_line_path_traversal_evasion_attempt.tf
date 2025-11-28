resource "azurerm_sentinel_alert_rule_scheduled" "potential_command_line_path_traversal_evasion_attempt" {
  name                       = "potential_command_line_path_traversal_evasion_attempt"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Command Line Path Traversal Evasion Attempt"
  description                = "Detects potential evasion or obfuscation attempts using bogus path traversal via the commandline - Google Drive - Citrix"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains "\\..\\Windows\\" or ProcessCommandLine contains "\\..\\System32\\" or ProcessCommandLine contains "\\..\\..\\") and FolderPath contains "\\Windows\\") or ProcessCommandLine contains ".exe\\..\\") and (not((ProcessCommandLine contains "\\Citrix\\Virtual Smart Card\\Citrix.Authentication.VirtualSmartcard.Launcher.exe\\..\\" or ProcessCommandLine contains "\\Google\\Drive\\googledrivesync.exe\\..\\")))
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
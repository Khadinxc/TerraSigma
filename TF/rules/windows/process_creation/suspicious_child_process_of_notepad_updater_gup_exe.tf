resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_child_process_of_notepad_updater_gup_exe" {
  name                       = "suspicious_child_process_of_notepad_updater_gup_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Child Process of Notepad++ Updater - GUP.Exe"
  description                = "Detects suspicious child process creation by the Notepad++ updater process (gup.exe). This could indicate potential exploitation of the updater component to deliver unwanted malware. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\gup.exe" and ((ProcessCommandLine contains "bitsadmin" or ProcessCommandLine contains "certutil" or ProcessCommandLine contains "curl" or ProcessCommandLine contains "finger" or ProcessCommandLine contains "forfiles" or ProcessCommandLine contains "regsvr32" or ProcessCommandLine contains "rundll32" or ProcessCommandLine contains "wget") or (FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\mshta.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection", "CredentialAccess", "InitialAccess"]
  techniques                 = ["T1195", "T1557"]
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
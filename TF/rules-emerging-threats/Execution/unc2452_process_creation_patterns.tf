resource "azurerm_sentinel_alert_rule_scheduled" "unc2452_process_creation_patterns" {
  name                       = "unc2452_process_creation_patterns"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UNC2452 Process Creation Patterns"
  description                = "Detects a specific process creation patterns as seen used by UNC2452 and provided by Microsoft as Microsoft Defender ATP queries"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "7z.exe a -v500m -mx9 -r0 -p" or ProcessCommandLine contains "7z.exe a -mx9 -r0 -p") and (ProcessCommandLine contains ".zip" and ProcessCommandLine contains ".txt")) or ((ProcessCommandLine contains "7z.exe a -v500m -mx9 -r0 -p" or ProcessCommandLine contains "7z.exe a -mx9 -r0 -p") and (ProcessCommandLine contains ".zip" and ProcessCommandLine contains ".log")) or ((ProcessCommandLine contains "rundll32.exe" and ProcessCommandLine contains "C:\\Windows" and ProcessCommandLine contains ".dll,Tk_") and (InitiatingProcessCommandLine contains "wscript.exe" and InitiatingProcessCommandLine contains ".vbs")) or (ProcessCommandLine contains "cmd.exe /C " and (InitiatingProcessCommandLine contains "C:\\Windows" and InitiatingProcessCommandLine contains ".dll") and InitiatingProcessFolderPath endswith "\\rundll32.exe") or (ProcessCommandLine =~ "" and FolderPath endswith "\\dllhost.exe" and InitiatingProcessFolderPath endswith "\\rundll32.exe")
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
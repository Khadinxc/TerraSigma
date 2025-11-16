resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_powershell_encoded_command_patterns" {
  name                       = "suspicious_powershell_encoded_command_patterns"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious PowerShell Encoded Command Patterns"
  description                = "Detects PowerShell command line patterns in combincation with encoded commands that often appear in malware infection chains - Other tools that work with encoded scripts in the command line instead of script files"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " JAB" or ProcessCommandLine contains " SUVYI" or ProcessCommandLine contains " SQBFAFgA" or ProcessCommandLine contains " aWV4I" or ProcessCommandLine contains " IAB" or ProcessCommandLine contains " PAA" or ProcessCommandLine contains " aQBlAHgA") and (ProcessCommandLine contains " -e " or ProcessCommandLine contains " -en " or ProcessCommandLine contains " -enc " or ProcessCommandLine contains " -enco") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.Exe", "pwsh.dll")))) and (not((InitiatingProcessFolderPath contains "C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\" or InitiatingProcessFolderPath contains "\\gc_worker.exe")))
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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
resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_encoded_powershell_command_line" {
  name                       = "suspicious_encoded_powershell_command_line"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Encoded PowerShell Command Line"
  description                = "Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll"))) and (((ProcessCommandLine contains " JAB" or ProcessCommandLine contains " SUVYI" or ProcessCommandLine contains " SQBFAFgA" or ProcessCommandLine contains " aQBlAHgA" or ProcessCommandLine contains " aWV4I" or ProcessCommandLine contains " IAA" or ProcessCommandLine contains " IAB" or ProcessCommandLine contains " UwB" or ProcessCommandLine contains " cwB") and ProcessCommandLine contains " -e") or (ProcessCommandLine contains ".exe -ENCOD " or ProcessCommandLine contains " BA^J e-")) and (not(ProcessCommandLine contains " -ExecutionPolicy remotesigned "))
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
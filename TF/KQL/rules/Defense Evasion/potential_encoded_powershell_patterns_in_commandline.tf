resource "azurerm_sentinel_alert_rule_scheduled" "potential_encoded_powershell_patterns_in_commandline" {
  name                       = "potential_encoded_powershell_patterns_in_commandline"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Encoded PowerShell Patterns In CommandLine"
  description                = "Detects specific combinations of encoding methods in PowerShell via the commandline"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll"))) and (((ProcessCommandLine contains "ToInt" or ProcessCommandLine contains "ToDecimal" or ProcessCommandLine contains "ToByte" or ProcessCommandLine contains "ToUint" or ProcessCommandLine contains "ToSingle" or ProcessCommandLine contains "ToSByte") and (ProcessCommandLine contains "ToChar" or ProcessCommandLine contains "ToString" or ProcessCommandLine contains "String")) or ((ProcessCommandLine contains "char" and ProcessCommandLine contains "join") or (ProcessCommandLine contains "split" and ProcessCommandLine contains "join")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1027", "T1059"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_powershell_iex_execution_patterns" {
  name                       = "suspicious_powershell_iex_execution_patterns"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious PowerShell IEX Execution Patterns"
  description                = "Detects suspicious ways to run Invoke-Execution using IEX alias - Legitimate scripts that use IEX"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains " | iex;" or ProcessCommandLine contains " | iex " or ProcessCommandLine contains " | iex}" or ProcessCommandLine contains " | IEX ;" or ProcessCommandLine contains " | IEX -Error" or ProcessCommandLine contains " | IEX (new" or ProcessCommandLine contains ");IEX ") and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe")) and (ProcessCommandLine contains "::FromBase64String" or ProcessCommandLine contains ".GetString([System.Convert]::")) or (ProcessCommandLine contains ")|iex;$" or ProcessCommandLine contains ");iex($" or ProcessCommandLine contains ");iex $" or ProcessCommandLine contains " | IEX | " or ProcessCommandLine contains " | iex\\\"")
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
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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
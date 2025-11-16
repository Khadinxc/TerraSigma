resource "azurerm_sentinel_alert_rule_scheduled" "execute_code_with_pester_bat_as_parent" {
  name                       = "execute_code_with_pester_bat_as_parent"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Execute Code with Pester.bat as Parent"
  description                = "Detects code execution via Pester.bat (Pester - Powershell Modulte for testing) - Legitimate use of Pester for writing tests for Powershell scripts and modules"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessCommandLine contains "{ Invoke-Pester -EnableExit ;" or InitiatingProcessCommandLine contains "{ Get-Help \"") and (InitiatingProcessCommandLine contains "\\WindowsPowerShell\\Modules\\Pester\\" and (InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1059", "T1216"]
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
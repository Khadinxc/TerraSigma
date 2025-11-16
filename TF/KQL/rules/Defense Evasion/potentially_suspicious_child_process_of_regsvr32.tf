resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_child_process_of_regsvr32" {
  name                       = "potentially_suspicious_child_process_of_regsvr32"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Child Process Of Regsvr32"
  description                = "Detects potentially suspicious child processes of \"regsvr32.exe\". - Unlikely, but can rarely occur. Apply additional filters accordingly."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\calc.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\explorer.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe" or FolderPath endswith "\\nltest.exe" or FolderPath endswith "\\notepad.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\reg.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\werfault.exe" or FolderPath endswith "\\wscript.exe") and InitiatingProcessFolderPath endswith "\\regsvr32.exe") and (not((ProcessCommandLine contains " -u -p " and FolderPath endswith "\\werfault.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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
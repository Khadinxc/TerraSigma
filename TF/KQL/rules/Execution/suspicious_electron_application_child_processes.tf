resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_electron_application_child_processes" {
  name                       = "suspicious_electron_application_child_processes"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Electron Application Child Processes"
  description                = "Detects suspicious child processes of electron apps (teams, discord, slack, etc.). This could be a potential sign of \".asar\" file tampering (See reference section for more information) or binary execution proxy through specific CLI arguments (see related rule)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessFolderPath endswith "\\chrome.exe" or InitiatingProcessFolderPath endswith "\\discord.exe" or InitiatingProcessFolderPath endswith "\\GitHubDesktop.exe" or InitiatingProcessFolderPath endswith "\\keybase.exe" or InitiatingProcessFolderPath endswith "\\msedge.exe" or InitiatingProcessFolderPath endswith "\\msedgewebview2.exe" or InitiatingProcessFolderPath endswith "\\msteams.exe" or InitiatingProcessFolderPath endswith "\\slack.exe" or InitiatingProcessFolderPath endswith "\\teams.exe") and ((FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\whoami.exe" or FolderPath endswith "\\wscript.exe") or (FolderPath contains ":\\ProgramData\\" or FolderPath contains ":\\Temp\\" or FolderPath contains "\\AppData\\Local\\Temp\\" or FolderPath contains "\\Users\\Public\\" or FolderPath contains "\\Windows\\Temp\\")) and (not((ProcessCommandLine contains "\\NVSMI\\nvidia-smi.exe" and FolderPath endswith "\\cmd.exe" and InitiatingProcessFolderPath endswith "\\Discord.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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
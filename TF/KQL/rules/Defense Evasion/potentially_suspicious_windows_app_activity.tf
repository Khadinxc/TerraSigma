resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_windows_app_activity" {
  name                       = "potentially_suspicious_windows_app_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Windows App Activity"
  description                = "Detects potentially suspicious child process of applications launched from inside the WindowsApps directory. This could be a sign of a rogue \".appx\" package installation/execution - Legitimate packages that make use of external binaries such as Windows Terminal"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath contains "C:\\Program Files\\WindowsApps\\" and ((ProcessCommandLine contains "cmd /c" or ProcessCommandLine contains "Invoke-" or ProcessCommandLine contains "Base64") or (FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\wscript.exe")) and (not(((FolderPath endswith "\\cmd.exe" and InitiatingProcessFolderPath startswith "C:\\Program Files\\WindowsApps\\Microsoft.SysinternalsSuite") or ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\pwsh.exe") and InitiatingProcessFolderPath contains ":\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal" and InitiatingProcessFolderPath endswith "\\WindowsTerminal.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
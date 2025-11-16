resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_electron_application_commandline" {
  name                       = "potentially_suspicious_electron_application_commandline"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Electron Application CommandLine"
  description                = "Detects potentially suspicious CommandLine of electron apps (teams, discord, slack, etc.). This could be a sign of abuse to proxy execution through a signed binary. - Legitimate usage for debugging purposes"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "--browser-subprocess-path" or ProcessCommandLine contains "--gpu-launcher" or ProcessCommandLine contains "--renderer-cmd-prefix" or ProcessCommandLine contains "--utility-cmd-prefix") and ((FolderPath endswith "\\chrome.exe" or FolderPath endswith "\\code.exe" or FolderPath endswith "\\discord.exe" or FolderPath endswith "\\GitHubDesktop.exe" or FolderPath endswith "\\keybase.exe" or FolderPath endswith "\\msedge_proxy.exe" or FolderPath endswith "\\msedge.exe" or FolderPath endswith "\\msedgewebview2.exe" or FolderPath endswith "\\msteams.exe" or FolderPath endswith "\\slack.exe" or FolderPath endswith "\\Teams.exe") or (ProcessVersionInfoOriginalFileName in~ ("chrome.exe", "code.exe", "discord.exe", "GitHubDesktop.exe", "keybase.exe", "msedge_proxy.exe", "msedge.exe", "msedgewebview2.exe", "msteams.exe", "slack.exe", "Teams.exe")))
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
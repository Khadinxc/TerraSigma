resource "azurerm_sentinel_alert_rule_scheduled" "file_download_with_headless_browser" {
  name                       = "file_download_with_headless_browser"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Download with Headless Browser"
  description                = "Detects execution of chromium based browser in headless mode using the \"dump-dom\" command line to download files"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "--headless" and ProcessCommandLine contains "dump-dom" and ProcessCommandLine contains "http") and (FolderPath endswith "\\brave.exe" or FolderPath endswith "\\chrome.exe" or FolderPath endswith "\\msedge.exe" or FolderPath endswith "\\opera.exe" or FolderPath endswith "\\vivaldi.exe")) and (not(((ProcessCommandLine contains "--headless --disable-gpu --disable-extensions --disable-plugins --mute-audio --no-first-run --incognito --aggressive-cache-discard --dump-dom" and (FolderPath endswith "\\msedge.exe" or FolderPath endswith "\\msedgewebview2.exe" or FolderPath endswith "\\MicrosoftEdge.exe") and (FolderPath startswith "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\" or FolderPath startswith "C:\\Program Files (x86)\\Microsoft\\EdgeCore\\" or FolderPath startswith "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\" or FolderPath startswith "C:\\Program Files\\Microsoft\\Edge\\Application\\" or FolderPath startswith "C:\\Program Files\\Microsoft\\EdgeCore\\" or FolderPath startswith "C:\\Program Files\\Microsoft\\EdgeWebView\\" or FolderPath startswith "C:\\Program Files\\WindowsApps\\Microsoft.MicrosoftEdge")) or (ProcessCommandLine contains "--headless --disable-gpu --disable-extensions --disable-plugins --mute-audio --no-first-run --incognito --aggressive-cache-discard --dump-dom" and (FolderPath contains "\\AppData\\Local\\Microsoft\\WindowsApps\\" or FolderPath contains "\\Windows\\SystemApps\\Microsoft.MicrosoftEdge") and (FolderPath endswith "\\msedge.exe" or FolderPath endswith "\\MicrosoftEdge.exe")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CommandAndControl"]
  techniques                 = ["T1105", "T1564"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "file_download_from_browser_process_via_inline_url" {
  name                       = "file_download_from_browser_process_via_inline_url"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Download From Browser Process Via Inline URL"
  description                = "Detects execution of a browser process with a URL argument pointing to a file with a potentially interesting extension. This can be abused to download arbitrary files or to hide from the user for example by launching the browser in a minimized state."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine endswith ".7z" or ProcessCommandLine endswith ".dat" or ProcessCommandLine endswith ".dll" or ProcessCommandLine endswith ".exe" or ProcessCommandLine endswith ".hta" or ProcessCommandLine endswith ".ps1" or ProcessCommandLine endswith ".psm1" or ProcessCommandLine endswith ".txt" or ProcessCommandLine endswith ".vbe" or ProcessCommandLine endswith ".vbs" or ProcessCommandLine endswith ".zip") and ProcessCommandLine contains "http" and (FolderPath endswith "\\brave.exe" or FolderPath endswith "\\chrome.exe" or FolderPath endswith "\\msedge.exe" or FolderPath endswith "\\opera.exe" or FolderPath endswith "\\vivaldi.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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
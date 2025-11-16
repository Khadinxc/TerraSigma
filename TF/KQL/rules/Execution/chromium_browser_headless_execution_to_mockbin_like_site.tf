resource "azurerm_sentinel_alert_rule_scheduled" "chromium_browser_headless_execution_to_mockbin_like_site" {
  name                       = "chromium_browser_headless_execution_to_mockbin_like_site"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Chromium Browser Headless Execution To Mockbin Like Site"
  description                = "Detects the execution of a Chromium based browser process with the \"headless\" flag and a URL pointing to the mockbin.org service (which can be used to exfiltrate data)."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "--headless" and (FolderPath endswith "\\brave.exe" or FolderPath endswith "\\chrome.exe" or FolderPath endswith "\\msedge.exe" or FolderPath endswith "\\opera.exe" or FolderPath endswith "\\vivaldi.exe") and (ProcessCommandLine contains "://run.mocky" or ProcessCommandLine contains "://mockbin")
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
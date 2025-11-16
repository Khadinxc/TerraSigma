resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_non_browser_network_communication_with_google_api" {
  name                       = "suspicious_non_browser_network_communication_with_google_api"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Non-Browser Network Communication With Google API"
  description                = "Detects a non-browser process interacting with the Google API which could indicate the use of a covert C2 such as Google Sheet C2 (GC2-sheet) - Legitimate applications communicating with the \"googleapis.com\" endpoints that are not already in the exclusion list. This is environmental dependent and requires further testing and tuning."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where (RemoteUrl contains "drive.googleapis.com" or RemoteUrl contains "oauth2.googleapis.com" or RemoteUrl contains "sheets.googleapis.com" or RemoteUrl contains "www.googleapis.com") and (not((InitiatingProcessFolderPath =~ "" or isnull(InitiatingProcessFolderPath)))) and (not((InitiatingProcessFolderPath endswith "\\brave.exe" or (InitiatingProcessFolderPath endswith ":\\Program Files\\Google\\Chrome\\Application\\chrome.exe" or InitiatingProcessFolderPath endswith ":\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe") or (InitiatingProcessFolderPath contains ":\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\" or (InitiatingProcessFolderPath endswith ":\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" or InitiatingProcessFolderPath endswith ":\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe" or InitiatingProcessFolderPath endswith "\\WindowsApps\\MicrosoftEdge.exe")) or ((InitiatingProcessFolderPath contains ":\\Program Files (x86)\\Microsoft\\EdgeCore\\" or InitiatingProcessFolderPath contains ":\\Program Files\\Microsoft\\EdgeCore\\") and (InitiatingProcessFolderPath endswith "\\msedge.exe" or InitiatingProcessFolderPath endswith "\\msedgewebview2.exe")) or (InitiatingProcessFolderPath endswith ":\\Program Files\\Mozilla Firefox\\firefox.exe" or InitiatingProcessFolderPath endswith ":\\Program Files (x86)\\Mozilla Firefox\\firefox.exe") or (InitiatingProcessFolderPath contains ":\\Program Files\\Google\\Drive File Stream\\" and InitiatingProcessFolderPath endswith "\\GoogleDriveFS.exe") or InitiatingProcessFolderPath endswith "\\GoogleUpdate.exe" or (InitiatingProcessFolderPath endswith ":\\Program Files (x86)\\Internet Explorer\\iexplore.exe" or InitiatingProcessFolderPath endswith ":\\Program Files\\Internet Explorer\\iexplore.exe") or InitiatingProcessFolderPath endswith "\\maxthon.exe" or InitiatingProcessFolderPath endswith "\\opera.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe" or InitiatingProcessFolderPath endswith "\\safari.exe" or InitiatingProcessFolderPath endswith "\\seamonkey.exe" or InitiatingProcessFolderPath endswith "\\vivaldi.exe" or InitiatingProcessFolderPath endswith "\\whale.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1102"]
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
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "URL"
    field_mapping {
      identifier  = "Url"
      column_name = "RemoteUrl"
    }
  }
}
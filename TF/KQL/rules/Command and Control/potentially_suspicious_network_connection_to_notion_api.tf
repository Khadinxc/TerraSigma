resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_network_connection_to_notion_api" {
  name                       = "potentially_suspicious_network_connection_to_notion_api"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Network Connection To Notion API"
  description                = "Detects a non-browser process communicating with the Notion API. This could indicate potential use of a covert C2 channel such as \"OffensiveNotion C2\" - Legitimate applications communicating with the \"api.notion.com\" endpoint that are not already in the exclusion list. The desktop and browser applications do not appear to be using the API by default unless integrations are configured."
  severity                   = "Low"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemoteUrl contains "api.notion.com" and (not((InitiatingProcessFolderPath endswith "\\brave.exe" or (InitiatingProcessFolderPath in~ ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe")) or (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\" or InitiatingProcessFolderPath endswith "\\WindowsApps\\MicrosoftEdge.exe" or (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"))) or ((InitiatingProcessFolderPath endswith "\\msedge.exe" or InitiatingProcessFolderPath endswith "\\msedgewebview2.exe") and (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft\\EdgeCore\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft\\EdgeCore\\")) or (InitiatingProcessFolderPath in~ ("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe")) or (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe", "C:\\Program Files\\Internet Explorer\\iexplore.exe")) or InitiatingProcessFolderPath endswith "\\maxthon.exe" or InitiatingProcessFolderPath endswith "\\AppData\\Local\\Programs\\Notion\\Notion.exe" or InitiatingProcessFolderPath endswith "\\opera.exe" or InitiatingProcessFolderPath endswith "\\safari.exe" or InitiatingProcessFolderPath endswith "\\seamonkey.exe" or InitiatingProcessFolderPath endswith "\\vivaldi.exe" or InitiatingProcessFolderPath endswith "\\whale.exe")))
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
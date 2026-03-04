resource "azurerm_sentinel_alert_rule_scheduled" "net_connection_win_domain_telegram_api_non_browser_access" {
  name                       = "net_connection_win_domain_telegram_api_non_browser_access"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Non-Browser Network Communication With Telegram API"
  description                = "Detects an a non-browser process interacting with the Telegram API which could indicate use of a covert C2 Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_domain_telegram_api_non_browser_access.yml - Legitimate applications communicating with the Telegram API e.g. web browsers not in the exclusion list, app with an RSS  etc. | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_domain_telegram_api_non_browser_access.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemoteUrl contains "api.telegram.org" and (not((InitiatingProcessFolderPath endswith "\\brave.exe" or (InitiatingProcessFolderPath in~ ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe")) or (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\" or InitiatingProcessFolderPath endswith "\\WindowsApps\\MicrosoftEdge.exe" or (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"))) or ((InitiatingProcessFolderPath endswith "\\msedge.exe" or InitiatingProcessFolderPath endswith "\\msedgewebview2.exe") and (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft\\EdgeCore\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft\\EdgeCore\\")) or (InitiatingProcessFolderPath in~ ("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe")) or (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe", "C:\\Program Files\\Internet Explorer\\iexplore.exe")) or InitiatingProcessFolderPath endswith "\\maxthon.exe" or InitiatingProcessFolderPath endswith "\\opera.exe" or InitiatingProcessFolderPath endswith "\\safari.exe" or InitiatingProcessFolderPath endswith "\\seamonkey.exe" or InitiatingProcessFolderPath endswith "\\vivaldi.exe" or InitiatingProcessFolderPath endswith "\\whale.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl", "Exfiltration"]
  techniques                 = ["T1102", "T1567", "T1105"]
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "RemoteIP"
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
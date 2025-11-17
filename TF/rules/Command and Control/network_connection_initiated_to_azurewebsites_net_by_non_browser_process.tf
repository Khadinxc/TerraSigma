resource "azurerm_sentinel_alert_rule_scheduled" "network_connection_initiated_to_azurewebsites_net_by_non_browser_process" {
  name                       = "network_connection_initiated_to_azurewebsites_net_by_non_browser_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Network Connection Initiated To AzureWebsites.NET By Non-Browser Process"
  description                = "Detects an initiated network connection by a non browser process on the system to \"azurewebsites.net\". The latter was often used by threat actors as a malware hosting and exfiltration site."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemoteUrl endswith "azurewebsites.net" and (not(((InitiatingProcessFolderPath endswith "\\avant.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Avant Browser\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Avant Browser\\")) or (InitiatingProcessFolderPath endswith "\\brave.exe" and InitiatingProcessFolderPath startswith "C:\\Program Files\\BraveSoftware\\") or (InitiatingProcessFolderPath in~ ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe")) or (InitiatingProcessFolderPath endswith "\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe" and InitiatingProcessFolderPath startswith "C:\\Users\\") or ((InitiatingProcessFolderPath contains "C:\\Program Files\\Windows Defender Advanced Threat Protection\\" or InitiatingProcessFolderPath contains "C:\\Program Files\\Windows Defender\\" or InitiatingProcessFolderPath contains "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\") and (InitiatingProcessFolderPath endswith "\\MsMpEng.exe" or InitiatingProcessFolderPath endswith "\\MsSense.exe")) or (InitiatingProcessFolderPath contains "\\AppData\\Local\\Discord\\" and InitiatingProcessFolderPath endswith "\\Discord.exe") or (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\" or InitiatingProcessFolderPath endswith "\\WindowsApps\\MicrosoftEdge.exe" or (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"))) or ((InitiatingProcessFolderPath endswith "\\msedge.exe" or InitiatingProcessFolderPath endswith "\\msedgewebview2.exe") and (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft\\EdgeCore\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft\\EdgeCore\\")) or InitiatingProcessFolderPath =~ "" or (InitiatingProcessFolderPath endswith "\\falkon.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Falkon\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Falkon\\")) or (InitiatingProcessFolderPath in~ ("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe")) or (InitiatingProcessFolderPath endswith "\\AppData\\Local\\Mozilla Firefox\\firefox.exe" and InitiatingProcessFolderPath startswith "C:\\Users\\") or (InitiatingProcessFolderPath contains "\\AppData\\Local\\Flock\\" and InitiatingProcessFolderPath endswith "\\Flock.exe") or (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe", "C:\\Program Files\\Internet Explorer\\iexplore.exe")) or (InitiatingProcessFolderPath contains "\\AppData\\Local\\Maxthon\\" and InitiatingProcessFolderPath endswith "\\maxthon.exe") or isnull(InitiatingProcessFolderPath) or (InitiatingProcessFolderPath contains "\\AppData\\Local\\Programs\\Opera\\" and InitiatingProcessFolderPath endswith "\\opera.exe") or (InitiatingProcessFolderPath contains "\\AppData\\Local\\Phoebe\\" and InitiatingProcessFolderPath endswith "\\Phoebe.exe") or (InitiatingProcessFolderPath endswith "C:\\Program Files (x86)\\PRTG Network Monitor\\PRTG Probe.exe" or InitiatingProcessFolderPath endswith "C:\\Program Files\\PRTG Network Monitor\\PRTG Probe.exe") or (InitiatingProcessFolderPath endswith "\\QtWeb.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\QtWeb\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\QtWeb\\")) or ((InitiatingProcessFolderPath contains "C:\\Program Files (x86)\\Safari\\" or InitiatingProcessFolderPath contains "C:\\Program Files\\Safari\\") and InitiatingProcessFolderPath endswith "\\safari.exe") or (InitiatingProcessFolderPath endswith "\\seamonkey.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files\\SeaMonkey\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\SeaMonkey\\")) or (InitiatingProcessFolderPath endswith "\\slimbrowser.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files\\SlimBrowser\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\SlimBrowser\\")) or (InitiatingProcessFolderPath contains "\\AppData\\Local\\Vivaldi\\" and InitiatingProcessFolderPath endswith "\\vivaldi.exe") or (InitiatingProcessFolderPath endswith "\\whale.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Naver\\Naver Whale\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Naver\\Naver Whale\\")) or (InitiatingProcessFolderPath endswith "\\Waterfox.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Waterfox\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Waterfox\\")))))
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
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
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
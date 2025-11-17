resource "azurerm_sentinel_alert_rule_scheduled" "network_connection_initiated_from_process_located_in_potentially_suspicious_or_uncommon_location" {
  name                       = "network_connection_initiated_from_process_located_in_potentially_suspicious_or_uncommon_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Network Connection Initiated From Process Located In Potentially Suspicious Or Uncommon Location"
  description                = "Detects a network connection initiated by programs or processes running from suspicious or uncommon files system locations."
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where (InitiatingProcessFolderPath contains ":\\$Recycle.bin" or InitiatingProcessFolderPath contains ":\\Perflogs\\" or InitiatingProcessFolderPath contains ":\\Temp\\" or InitiatingProcessFolderPath contains ":\\Users\\Default\\" or InitiatingProcessFolderPath contains ":\\Windows\\Fonts\\" or InitiatingProcessFolderPath contains ":\\Windows\\IME\\" or InitiatingProcessFolderPath contains ":\\Windows\\System32\\Tasks\\" or InitiatingProcessFolderPath contains ":\\Windows\\Tasks\\" or InitiatingProcessFolderPath contains "\\config\\systemprofile\\" or InitiatingProcessFolderPath contains "\\Windows\\addins\\") and (not((RemoteUrl endswith ".githubusercontent.com" or RemoteUrl endswith "anonfiles.com" or RemoteUrl endswith "cdn.discordapp.com" or RemoteUrl endswith "ddns.net" or RemoteUrl endswith "dl.dropboxusercontent.com" or RemoteUrl endswith "ghostbin.co" or RemoteUrl endswith "glitch.me" or RemoteUrl endswith "gofile.io" or RemoteUrl endswith "hastebin.com" or RemoteUrl endswith "mediafire.com" or RemoteUrl endswith "mega.co.nz" or RemoteUrl endswith "mega.nz" or RemoteUrl endswith "onrender.com" or RemoteUrl endswith "pages.dev" or RemoteUrl endswith "paste.ee" or RemoteUrl endswith "pastebin.com" or RemoteUrl endswith "pastebin.pl" or RemoteUrl endswith "pastetext.net" or RemoteUrl endswith "portmap.io" or RemoteUrl endswith "privatlab.com" or RemoteUrl endswith "privatlab.net" or RemoteUrl endswith "send.exploit.in" or RemoteUrl endswith "sendspace.com" or RemoteUrl endswith "storage.googleapis.com" or RemoteUrl endswith "storjshare.io" or RemoteUrl endswith "supabase.co" or RemoteUrl endswith "temp.sh" or RemoteUrl endswith "transfer.sh" or RemoteUrl endswith "trycloudflare.com" or RemoteUrl endswith "ufile.io" or RemoteUrl endswith "w3spaces.com" or RemoteUrl endswith "workers.dev")))
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
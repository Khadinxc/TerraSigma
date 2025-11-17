resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_azure_front_door_connection" {
  name                       = "potentially_suspicious_azure_front_door_connection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Azure Front Door Connection"
  description                = "Detects connections with Azure Front Door (known legitimate service that can be leveraged for C2) that fall outside of known benign behavioral baseline (not using common apps or common azurefd.net endpoints) - Results are not inherently suspicious, but should be investigated during threat hunting for potential cloud C2. - Organization-specific Azure Front Door endpoints"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemoteUrl contains "azurefd.net" and (not((InitiatingProcessFolderPath endswith "searchapp.exe" or (RemoteUrl contains "afdxtest.z01.azurefd.net" or RemoteUrl contains "fp-afd.azurefd.net" or RemoteUrl contains "fp-afdx-bpdee4gtg6frejfd.z01.azurefd.net" or RemoteUrl contains "roxy.azurefd.net" or RemoteUrl contains "powershellinfraartifacts-gkhedzdeaghdezhr.z01.azurefd.net" or RemoteUrl contains "storage-explorer-publishing-feapcgfgbzc2cjek.b01.azurefd.net" or RemoteUrl contains "graph.azurefd.net") or (InitiatingProcessFolderPath endswith "brave.exe" or InitiatingProcessFolderPath endswith "chrome.exe" or InitiatingProcessFolderPath endswith "chromium.exe" or InitiatingProcessFolderPath endswith "firefox.exe" or InitiatingProcessFolderPath endswith "msedge.exe" or InitiatingProcessFolderPath endswith "msedgewebview2.exe" or InitiatingProcessFolderPath endswith "opera.exe" or InitiatingProcessFolderPath endswith "vivaldi.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1102", "T1090"]
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
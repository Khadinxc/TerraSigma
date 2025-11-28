resource "azurerm_sentinel_alert_rule_scheduled" "office_macro_file_download" {
  name                       = "office_macro_file_download"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Office Macro File Download"
  description                = "Detects the creation of a new office macro files on the system via an application (browser, mail client). This can help identify potential malicious activity, such as the download of macro-enabled documents that could be used for exploitation. - Legitimate macro files downloaded from the internet - Legitimate macro files sent as attachments via emails"
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where ((FolderPath endswith ".docm" or FolderPath endswith ".dotm" or FolderPath endswith ".xlsm" or FolderPath endswith ".xltm" or FolderPath endswith ".potm" or FolderPath endswith ".pptm") or (FolderPath contains ".docm:Zone" or FolderPath contains ".dotm:Zone" or FolderPath contains ".xlsm:Zone" or FolderPath contains ".xltm:Zone" or FolderPath contains ".potm:Zone" or FolderPath contains ".pptm:Zone")) and (InitiatingProcessFolderPath endswith "\\RuntimeBroker.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe" or InitiatingProcessFolderPath endswith "\\thunderbird.exe" or InitiatingProcessFolderPath endswith "\\brave.exe" or InitiatingProcessFolderPath endswith "\\chrome.exe" or InitiatingProcessFolderPath endswith "\\firefox.exe" or InitiatingProcessFolderPath endswith "\\iexplore.exe" or InitiatingProcessFolderPath endswith "\\maxthon.exe" or InitiatingProcessFolderPath endswith "\\MicrosoftEdge.exe" or InitiatingProcessFolderPath endswith "\\msedge.exe" or InitiatingProcessFolderPath endswith "\\msedgewebview2.exe" or InitiatingProcessFolderPath endswith "\\opera.exe" or InitiatingProcessFolderPath endswith "\\safari.exe" or InitiatingProcessFolderPath endswith "\\seamonkey.exe" or InitiatingProcessFolderPath endswith "\\vivaldi.exe" or InitiatingProcessFolderPath endswith "\\whale.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1566"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
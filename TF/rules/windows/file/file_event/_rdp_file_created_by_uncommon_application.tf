resource "azurerm_sentinel_alert_rule_scheduled" "rdp_file_created_by_uncommon_application" {
  name                       = "rdp_file_created_by_uncommon_application"
  log_analytics_workspace_id = var.workspace_id
  display_name               = ".RDP File Created By Uncommon Application"
  description                = "Detects creation of a file with an \".rdp\" extension by an application that doesn't commonly create such files."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\brave.exe" or InitiatingProcessFolderPath endswith "\\CCleaner Browser\\Application\\CCleanerBrowser.exe" or InitiatingProcessFolderPath endswith "\\chromium.exe" or InitiatingProcessFolderPath endswith "\\firefox.exe" or InitiatingProcessFolderPath endswith "\\Google\\Chrome\\Application\\chrome.exe" or InitiatingProcessFolderPath endswith "\\iexplore.exe" or InitiatingProcessFolderPath endswith "\\microsoftedge.exe" or InitiatingProcessFolderPath endswith "\\msedge.exe" or InitiatingProcessFolderPath endswith "\\Opera.exe" or InitiatingProcessFolderPath endswith "\\Vivaldi.exe" or InitiatingProcessFolderPath endswith "\\Whale.exe" or InitiatingProcessFolderPath endswith "\\olk.exe" or InitiatingProcessFolderPath endswith "\\Outlook.exe" or InitiatingProcessFolderPath endswith "\\RuntimeBroker.exe" or InitiatingProcessFolderPath endswith "\\Thunderbird.exe" or InitiatingProcessFolderPath endswith "\\Discord.exe" or InitiatingProcessFolderPath endswith "\\Keybase.exe" or InitiatingProcessFolderPath endswith "\\msteams.exe" or InitiatingProcessFolderPath endswith "\\Slack.exe" or InitiatingProcessFolderPath endswith "\\teams.exe") and FolderPath endswith ".rdp"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
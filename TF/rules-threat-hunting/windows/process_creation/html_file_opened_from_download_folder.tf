resource "azurerm_sentinel_alert_rule_scheduled" "html_file_opened_from_download_folder" {
  name                       = "html_file_opened_from_download_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HTML File Opened From Download Folder"
  description                = "Detects web browser process opening an HTML file from a user's Downloads folder. This behavior is could be associated with phishing attacks where threat actors send HTML attachments to users. When a user opens such an attachment, it can lead to the execution of malicious scripts or the download of malware. During investigation, analyze the HTML file for embedded scripts or links, check for any subsequent downloads or process executions, and investigate the source of the email or message containing the attachment. - Opening any HTML file located in users directories via a browser process will trigger this."
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ":\\users\\" and ProcessCommandLine contains "\\Downloads\\" and ProcessCommandLine contains ".htm") and (FolderPath endswith "\\brave.exe" or FolderPath endswith "\\chrome.exe" or FolderPath endswith "\\firefox.exe" or FolderPath endswith "\\msedge.exe" or FolderPath endswith "\\opera.exe" or FolderPath endswith "\\vivaldi.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Reconnaissance"]
  techniques                 = ["T1598", "T1566"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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
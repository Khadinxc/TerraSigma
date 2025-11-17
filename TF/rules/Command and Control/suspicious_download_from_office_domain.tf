resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_download_from_office_domain" {
  name                       = "suspicious_download_from_office_domain"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Download from Office Domain"
  description                = "Detects suspicious ways to download files from Microsoft domains that are used to store attachments in Emails or OneNote documents - Scripts or tools that download attachments from these domains (OneNote, Outlook 365)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "https://attachment.outlook.live.net/owa/" or ProcessCommandLine contains "https://onenoteonlinesync.onenote.com/onenoteonlinesync/") and ((FolderPath endswith "\\curl.exe" or FolderPath endswith "\\wget.exe") or (ProcessCommandLine contains "Invoke-WebRequest" or ProcessCommandLine contains "iwr " or ProcessCommandLine contains "curl " or ProcessCommandLine contains "wget " or ProcessCommandLine contains "Start-BitsTransfer" or ProcessCommandLine contains ".DownloadFile(" or ProcessCommandLine contains ".DownloadString("))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl", "ResourceDevelopment"]
  techniques                 = ["T1105", "T1608"]
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
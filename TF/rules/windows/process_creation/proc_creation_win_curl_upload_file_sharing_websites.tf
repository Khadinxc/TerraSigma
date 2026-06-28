resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_curl_upload_file_sharing_websites" {
  name                       = "proc_creation_win_curl_upload_file_sharing_websites"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Curl File Upload To File Sharing Websites"
  description                = <<DESC
    Detects usage of curl to upload files to known file sharing domains, which may indicate data exfiltration.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_curl_upload_file_sharing_websites.yml

    False Positives:
    - Legitimate file uploads to these services by administrators or developers
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "0x0.st" or ProcessCommandLine contains "bashupload.com" or ProcessCommandLine contains "chunk.io" or ProcessCommandLine contains "file.io" or ProcessCommandLine contains "filebin.net" or ProcessCommandLine contains "pastebin" or ProcessCommandLine contains "send.firefox.com" or ProcessCommandLine contains "temp.sh" or ProcessCommandLine contains "transfer.sh" or ProcessCommandLine contains "ufile.io" or ProcessCommandLine contains "uploadfiles.io" or ProcessCommandLine contains "wetransfer.com" or ProcessCommandLine contains "x0.at") and ((ProcessCommandLine contains " --form" or ProcessCommandLine contains " --upload-file" or ProcessCommandLine contains " --data" or ProcessCommandLine contains " -X POST" or ProcessCommandLine contains " --request POST ") or (ProcessCommandLine matches regex "\\s-[FTd]\\s" or ProcessCommandLine matches regex "\\s-sT\\s")) and (FolderPath endswith "\\curl.exe" or ProcessVersionInfoOriginalFileName =~ "curl.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1567"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
resource "azurerm_sentinel_alert_rule_scheduled" "file_download_from_ip_url_via_curl_exe" {
  name                       = "file_download_from_ip_url_via_curl_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Download From IP URL Via Curl.EXE"
  description                = "Detects file downloads directly from IP address URL using curl.exe"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -O" or ProcessCommandLine contains "--remote-name" or ProcessCommandLine contains "--output") and ProcessCommandLine contains "http" and (FolderPath endswith "\\curl.exe" or ProcessVersionInfoOriginalFileName =~ "curl.exe") and ProcessCommandLine matches regex "://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}") and (not((ProcessCommandLine endswith ".bat" or ProcessCommandLine endswith ".bat\"" or ProcessCommandLine endswith ".dat" or ProcessCommandLine endswith ".dat\"" or ProcessCommandLine endswith ".dll" or ProcessCommandLine endswith ".dll\"" or ProcessCommandLine endswith ".exe" or ProcessCommandLine endswith ".exe\"" or ProcessCommandLine endswith ".gif" or ProcessCommandLine endswith ".gif\"" or ProcessCommandLine endswith ".hta" or ProcessCommandLine endswith ".hta\"" or ProcessCommandLine endswith ".jpeg" or ProcessCommandLine endswith ".jpeg\"" or ProcessCommandLine endswith ".log" or ProcessCommandLine endswith ".log\"" or ProcessCommandLine endswith ".msi" or ProcessCommandLine endswith ".msi\"" or ProcessCommandLine endswith ".png" or ProcessCommandLine endswith ".png\"" or ProcessCommandLine endswith ".ps1" or ProcessCommandLine endswith ".ps1\"" or ProcessCommandLine endswith ".psm1" or ProcessCommandLine endswith ".psm1\"" or ProcessCommandLine endswith ".vbe" or ProcessCommandLine endswith ".vbe\"" or ProcessCommandLine endswith ".vbs" or ProcessCommandLine endswith ".vbs\"" or ProcessCommandLine endswith ".bat'" or ProcessCommandLine endswith ".dat'" or ProcessCommandLine endswith ".dll'" or ProcessCommandLine endswith ".exe'" or ProcessCommandLine endswith ".gif'" or ProcessCommandLine endswith ".hta'" or ProcessCommandLine endswith ".jpeg'" or ProcessCommandLine endswith ".log'" or ProcessCommandLine endswith ".msi'" or ProcessCommandLine endswith ".png'" or ProcessCommandLine endswith ".ps1'" or ProcessCommandLine endswith ".psm1'" or ProcessCommandLine endswith ".vbe'" or ProcessCommandLine endswith ".vbs'")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
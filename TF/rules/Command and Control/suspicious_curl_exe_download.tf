resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_curl_exe_download" {
  name                       = "suspicious_curl_exe_download"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Curl.EXE Download"
  description                = "Detects a suspicious curl process start on Windows and outputs the requested document to a local file"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\curl.exe" or ProcessVersionInfoProductName =~ "The curl executable") and ((ProcessCommandLine endswith ".dll" or ProcessCommandLine endswith ".gif" or ProcessCommandLine endswith ".jpeg" or ProcessCommandLine endswith ".jpg" or ProcessCommandLine endswith ".png" or ProcessCommandLine endswith ".temp" or ProcessCommandLine endswith ".tmp" or ProcessCommandLine endswith ".txt" or ProcessCommandLine endswith ".vbe" or ProcessCommandLine endswith ".vbs") or (ProcessCommandLine contains "%AppData%" or ProcessCommandLine contains "%Public%" or ProcessCommandLine contains "%Temp%" or ProcessCommandLine contains "%tmp%" or ProcessCommandLine contains "\\AppData\\" or ProcessCommandLine contains "\\Desktop\\" or ProcessCommandLine contains "\\Temp\\" or ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "C:\\PerfLogs\\" or ProcessCommandLine contains "C:\\ProgramData\\" or ProcessCommandLine contains "C:\\Windows\\Temp\\")) and (not(((ProcessCommandLine contains "--silent --show-error --output " and ProcessCommandLine contains "gfw-httpget-" and ProcessCommandLine contains "AppData") and FolderPath =~ "C:\\Program Files\\Git\\mingw64\\bin\\curl.exe" and InitiatingProcessFolderPath =~ "C:\\Program Files\\Git\\usr\\bin\\sh.exe")))
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
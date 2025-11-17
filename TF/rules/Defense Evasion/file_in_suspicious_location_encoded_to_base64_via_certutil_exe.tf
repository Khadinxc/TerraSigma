resource "azurerm_sentinel_alert_rule_scheduled" "file_in_suspicious_location_encoded_to_base64_via_certutil_exe" {
  name                       = "file_in_suspicious_location_encoded_to_base64_via_certutil_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File In Suspicious Location Encoded To Base64 Via Certutil.EXE"
  description                = "Detects the execution of certutil with the \"encode\" flag to encode a file to base64 where the files are located in potentially suspicious locations"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-encode" or ProcessCommandLine contains "/encode" or ProcessCommandLine contains "–encode" or ProcessCommandLine contains "—encode" or ProcessCommandLine contains "―encode") and (ProcessCommandLine contains "\\AppData\\Roaming\\" or ProcessCommandLine contains "\\Desktop\\" or ProcessCommandLine contains "\\Local\\Temp\\" or ProcessCommandLine contains "\\PerfLogs\\" or ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "\\Windows\\Temp\\" or ProcessCommandLine contains "$Recycle.Bin") and (FolderPath endswith "\\certutil.exe" or ProcessVersionInfoOriginalFileName =~ "CertUtil.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1027"]
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
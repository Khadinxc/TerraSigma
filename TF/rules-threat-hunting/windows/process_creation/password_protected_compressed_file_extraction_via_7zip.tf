resource "azurerm_sentinel_alert_rule_scheduled" "password_protected_compressed_file_extraction_via_7zip" {
  name                       = "password_protected_compressed_file_extraction_via_7zip"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Password Protected Compressed File Extraction Via 7Zip"
  description                = "Detects usage of 7zip utilities (7z.exe, 7za.exe and 7zr.exe) to extract password protected zip files. - Legitimate activity is expected since extracting files with a password can be common in some environment."
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessVersionInfoFileDescription contains "7-Zip" or (FolderPath endswith "\\7z.exe" or FolderPath endswith "\\7zr.exe" or FolderPath endswith "\\7za.exe") or (ProcessVersionInfoOriginalFileName in~ ("7z.exe", "7za.exe"))) and (ProcessCommandLine contains " -p" and ProcessCommandLine contains " x " and ProcessCommandLine contains " -o")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1560"]
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
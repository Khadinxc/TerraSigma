resource "azurerm_sentinel_alert_rule_scheduled" "self_extracting_package_creation_via_iexpress_exe_from_potentially_suspicious_location" {
  name                       = "self_extracting_package_creation_via_iexpress_exe_from_potentially_suspicious_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Self Extracting Package Creation Via Iexpress.EXE From Potentially Suspicious Location"
  description                = "Detects the use of iexpress.exe to create binaries via Self Extraction Directive (SED) files located in potentially suspicious locations. This behavior has been observed in-the-wild by different threat actors. - Administrators building packages using iexpress.exe"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -n " or ProcessCommandLine contains " /n " or ProcessCommandLine contains " –n " or ProcessCommandLine contains " —n " or ProcessCommandLine contains " ―n ") and (FolderPath endswith "\\iexpress.exe" or ProcessVersionInfoOriginalFileName =~ "IEXPRESS.exe") and (ProcessCommandLine contains ":\\ProgramData\\" or ProcessCommandLine contains ":\\Temp\\" or ProcessCommandLine contains ":\\Windows\\System32\\Tasks\\" or ProcessCommandLine contains ":\\Windows\\Tasks\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_dll_loaded_via_certoc_exe" {
  name                       = "suspicious_dll_loaded_via_certoc_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious DLL Loaded via CertOC.EXE"
  description                = "Detects when a user installs certificates by using CertOC.exe to load the target DLL file."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -LoadDLL " or ProcessCommandLine contains " /LoadDLL " or ProcessCommandLine contains " –LoadDLL " or ProcessCommandLine contains " —LoadDLL " or ProcessCommandLine contains " ―LoadDLL ") and (FolderPath endswith "\\certoc.exe" or ProcessVersionInfoOriginalFileName =~ "CertOC.exe") and (ProcessCommandLine contains "\\Appdata\\Local\\Temp\\" or ProcessCommandLine contains "\\Desktop\\" or ProcessCommandLine contains "\\Downloads\\" or ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "C:\\Windows\\Tasks\\" or ProcessCommandLine contains "C:\\Windows\\Temp\\")
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
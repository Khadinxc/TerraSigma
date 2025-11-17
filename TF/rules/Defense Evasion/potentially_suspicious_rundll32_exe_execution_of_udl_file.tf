resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_rundll32_exe_execution_of_udl_file" {
  name                       = "potentially_suspicious_rundll32_exe_execution_of_udl_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Rundll32.EXE Execution of UDL File"
  description                = "Detects the execution of rundll32.exe with the oledb32.dll library to open a UDL file. Threat actors can abuse this technique as a phishing vector to capture authentication credentials or other sensitive data. - UDL files serve as a convenient and flexible tool for managing and testing database connections in various development and administrative scenarios."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "oledb32.dll" and ProcessCommandLine contains ",OpenDSLFile " and (ProcessCommandLine contains "\\Users\\" and ProcessCommandLine contains "\\Downloads\\")) and ProcessCommandLine endswith ".udl") and (FolderPath endswith "\\rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE") and InitiatingProcessFolderPath endswith "\\explorer.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution", "CommandAndControl"]
  techniques                 = ["T1218", "T1071"]
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
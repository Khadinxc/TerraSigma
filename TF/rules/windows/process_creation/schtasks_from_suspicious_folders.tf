resource "azurerm_sentinel_alert_rule_scheduled" "schtasks_from_suspicious_folders" {
  name                       = "schtasks_from_suspicious_folders"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Schtasks From Suspicious Folders"
  description                = "Detects scheduled task creations that have suspicious action command and folder combinations"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "C:\\ProgramData\\" or ProcessCommandLine contains "%ProgramData%") and (ProcessCommandLine contains "powershell" or ProcessCommandLine contains "pwsh" or ProcessCommandLine contains "cmd /c " or ProcessCommandLine contains "cmd /k " or ProcessCommandLine contains "cmd /r " or ProcessCommandLine contains "cmd.exe /c " or ProcessCommandLine contains "cmd.exe /k " or ProcessCommandLine contains "cmd.exe /r ") and ProcessCommandLine contains " /create " and (FolderPath endswith "\\schtasks.exe" or ProcessVersionInfoOriginalFileName =~ "schtasks.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "Execution"]
  techniques                 = ["T1053"]
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
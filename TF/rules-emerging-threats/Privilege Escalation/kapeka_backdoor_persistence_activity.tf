resource "azurerm_sentinel_alert_rule_scheduled" "kapeka_backdoor_persistence_activity" {
  name                       = "kapeka_backdoor_persistence_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Kapeka Backdoor Persistence Activity"
  description                = "Detects Kapeka backdoor persistence activity. Depending on the process privileges, the Kapeka dropper then sets persistence for the backdoor either as a scheduled task (if admin or SYSTEM) or autorun registry (if not). For the scheduled task, it creates a scheduled task called \"Sens Api\" via schtasks command, which is set to run upon system startup as SYSTEM. To establish persistence through the autorun utility, it adds an autorun entry called \"Sens Api\" under HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run via the \"reg add\" command. Both persistence mechanisms are set to launch the binary by calling rundll32 and passing the backdoor's first export ordinal (#1) without any additional argument. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains "create" and ProcessCommandLine contains "ONSTART") and (FolderPath endswith "\\schtasks.exe" or ProcessVersionInfoOriginalFileName =~ "schtasks.exe")) or ((ProcessCommandLine contains "add" and ProcessCommandLine contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") and (FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe"))) and ((ProcessCommandLine contains "Sens Api" or ProcessCommandLine contains "OneDrive") and (ProcessCommandLine contains "rundll32" and ProcessCommandLine contains ".wll" and ProcessCommandLine contains "#1"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
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
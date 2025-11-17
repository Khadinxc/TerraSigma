resource "azurerm_sentinel_alert_rule_scheduled" "schedule_task_creation_from_env_variable_or_potentially_suspicious_path_via_schtasks_exe" {
  name                       = "schedule_task_creation_from_env_variable_or_potentially_suspicious_path_via_schtasks_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE"
  description                = "Detects Schtask creations that point to a suspicious folder or an environment variable often used by malware - Benign scheduled tasks creations or executions that happen often during software installations - Software that uses the AppData folder and scheduled tasks to update the software in the AppData folders"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains ":\\Perflogs" or ProcessCommandLine contains ":\\Users\\All Users\\" or ProcessCommandLine contains ":\\Users\\Default\\" or ProcessCommandLine contains ":\\Users\\Public" or ProcessCommandLine contains ":\\Windows\\Temp" or ProcessCommandLine contains "\\AppData\\Local\\" or ProcessCommandLine contains "\\AppData\\Roaming\\" or ProcessCommandLine contains "%AppData%" or ProcessCommandLine contains "%Public%") and ((ProcessCommandLine contains " -create " or ProcessCommandLine contains " /create " or ProcessCommandLine contains " –create " or ProcessCommandLine contains " —create " or ProcessCommandLine contains " ―create ") and FolderPath endswith "\\schtasks.exe")) or (InitiatingProcessCommandLine endswith "\\svchost.exe -k netsvcs -p -s Schedule" and (ProcessCommandLine contains ":\\Perflogs" or ProcessCommandLine contains ":\\Windows\\Temp" or ProcessCommandLine contains "\\Users\\Public" or ProcessCommandLine contains "%Public%"))) and (not(((ProcessCommandLine contains "/Create /Xml " and ProcessCommandLine contains "\\Temp\\.CR." and ProcessCommandLine contains "\\Avira_Security_Installation.xml") or ((ProcessCommandLine contains ".tmp\\UpdateFallbackTask.xml" or ProcessCommandLine contains ".tmp\\WatchdogServiceControlManagerTimeout.xml" or ProcessCommandLine contains ".tmp\\SystrayAutostart.xml" or ProcessCommandLine contains ".tmp\\MaintenanceTask.xml") and (ProcessCommandLine contains "/Create /F /TN" and ProcessCommandLine contains "/Xml " and ProcessCommandLine contains "\\Temp\\" and ProcessCommandLine contains "Avira_")) or (ProcessCommandLine contains "\\Temp\\" and ProcessCommandLine contains "/Create /TN \"klcp_update\" /XML " and ProcessCommandLine contains "\\klcp_update_task.xml") or (InitiatingProcessCommandLine contains "unattended.ini" or ProcessCommandLine contains "update_task.xml") or ProcessCommandLine contains "/Create /TN TVInstallRestore /TR")))
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
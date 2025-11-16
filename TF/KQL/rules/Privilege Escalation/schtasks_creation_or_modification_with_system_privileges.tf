resource "azurerm_sentinel_alert_rule_scheduled" "schtasks_creation_or_modification_with_system_privileges" {
  name                       = "schtasks_creation_or_modification_with_system_privileges"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Schtasks Creation Or Modification With SYSTEM Privileges"
  description                = "Detects the creation or update of a scheduled task to run with \"NT AUTHORITY\\SYSTEM\" privileges"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains " /change " or ProcessCommandLine contains " /create ") and FolderPath endswith "\\schtasks.exe") and ProcessCommandLine contains "/ru " and (ProcessCommandLine contains "NT AUT" or ProcessCommandLine contains " SYSTEM ")) and (not(((ProcessCommandLine contains "/Create /F /RU System /SC WEEKLY /TN AviraSystemSpeedupVerify /TR " or ProcessCommandLine contains ":\\Program Files (x86)\\Avira\\System Speedup\\setup\\avira_speedup_setup.exe" or ProcessCommandLine contains "/VERIFY /VERYSILENT /NOSTART /NODOTNET /NORESTART\" /RL HIGHEST") or (ProcessCommandLine contains "Subscription Heartbeat" and ProcessCommandLine contains "\\HeartbeatConfig.xml" and ProcessCommandLine contains "\\Microsoft Shared\\OFFICE") or ((ProcessCommandLine contains "/TN TVInstallRestore" and ProcessCommandLine contains "\\TeamViewer_.exe") and FolderPath endswith "\\schtasks.exe"))))
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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
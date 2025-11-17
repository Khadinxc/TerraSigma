resource "azurerm_sentinel_alert_rule_scheduled" "oilrig_apt_activity" {
  name                       = "oilrig_apt_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "OilRig APT Activity"
  description                = "Detects OilRig activity as reported by Nyotron in their March 2018 report - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "nslookup.exe" and ProcessCommandLine contains "-q=TXT") and InitiatingProcessFolderPath endswith "\\local\\microsoft\\Taskbar\\autoit3.exe") or (ProcessCommandLine contains "SC Scheduled Scan" and ProcessCommandLine contains "\\microsoft\\Taskbar\\autoit3.exe") or ((ProcessCommandLine contains "i" or ProcessCommandLine contains "u") and FolderPath =~ "C:\\Windows\\system32\\Service.exe") or (FolderPath contains "\\Windows\\Temp\\DB\\" and FolderPath endswith ".exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence", "DefenseEvasion", "CommandAndControl"]
  techniques                 = ["T1053", "T1543", "T1112", "T1071"]
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
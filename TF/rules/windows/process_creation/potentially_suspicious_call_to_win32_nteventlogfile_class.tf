resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_call_to_win32_nteventlogfile_class" {
  name                       = "potentially_suspicious_call_to_win32_nteventlogfile_class"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Call To Win32_NTEventlogFile Class"
  description                = "Detects usage of the WMI class \"Win32_NTEventlogFile\" in a potentially suspicious way (delete, backup, change permissions, etc.) from a PowerShell script"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "Win32_NTEventlogFile" and (ProcessCommandLine contains ".BackupEventlog(" or ProcessCommandLine contains ".ChangeSecurityPermissions(" or ProcessCommandLine contains ".ChangeSecurityPermissionsEx(" or ProcessCommandLine contains ".ClearEventLog(" or ProcessCommandLine contains ".Delete(" or ProcessCommandLine contains ".DeleteEx(" or ProcessCommandLine contains ".Rename(" or ProcessCommandLine contains ".TakeOwnerShip(" or ProcessCommandLine contains ".TakeOwnerShipEx(")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
}
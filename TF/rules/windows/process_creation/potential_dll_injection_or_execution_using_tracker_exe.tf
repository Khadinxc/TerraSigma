resource "azurerm_sentinel_alert_rule_scheduled" "potential_dll_injection_or_execution_using_tracker_exe" {
  name                       = "potential_dll_injection_or_execution_using_tracker_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential DLL Injection Or Execution Using Tracker.exe"
  description                = "Detects potential DLL injection and execution using \"Tracker.exe\""
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " /d " or ProcessCommandLine contains " /c ") and (FolderPath endswith "\\tracker.exe" or ProcessVersionInfoFileDescription =~ "Tracker")) and (not((ProcessCommandLine contains " /ERRORREPORT:PROMPT " or (InitiatingProcessFolderPath endswith "\\Msbuild\\Current\\Bin\\MSBuild.exe" or InitiatingProcessFolderPath endswith "\\Msbuild\\Current\\Bin\\amd64\\MSBuild.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1055"]
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
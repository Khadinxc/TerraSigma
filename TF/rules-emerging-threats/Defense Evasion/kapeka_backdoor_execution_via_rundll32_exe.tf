resource "azurerm_sentinel_alert_rule_scheduled" "kapeka_backdoor_execution_via_rundll32_exe" {
  name                       = "kapeka_backdoor_execution_via_rundll32_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Kapeka Backdoor Execution Via RunDLL32.EXE"
  description                = "Detects Kapeka backdoor process execution pattern, where the dropper launch the backdoor binary by calling rundll32 and passing the backdoor's first export ordinal (#1) with a \"-d\" argument."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE") and (ProcessCommandLine contains ":\\ProgramData" or ProcessCommandLine contains "\\AppData\\Local") and ((ProcessCommandLine contains ".wll" and ProcessCommandLine contains "#1" and ProcessCommandLine contains " -d") or (ProcessCommandLine contains ".wll" and ProcessCommandLine endswith "#1"))
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
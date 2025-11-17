resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_rundll32_setupapi_dll_activity" {
  name                       = "suspicious_rundll32_setupapi_dll_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Rundll32 Setupapi.dll Activity"
  description                = "setupapi.dll library provide InstallHinfSection function for processing INF files. INF file may contain instructions allowing to create values in the registry, modify files and install drivers. This technique could be used to obtain persistence via modifying one of Run or RunOnce registry keys, run process or use other DLLs chain calls (see references) InstallHinfSection function in setupapi.dll calls runonce.exe executable regardless of actual content of INF file. - Scripts and administrative tools that use INF files for driver installation with setupapi.dll"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\runonce.exe" and (InitiatingProcessCommandLine contains "setupapi.dll" and InitiatingProcessCommandLine contains "InstallHinfSection") and InitiatingProcessFolderPath endswith "\\rundll32.exe"
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
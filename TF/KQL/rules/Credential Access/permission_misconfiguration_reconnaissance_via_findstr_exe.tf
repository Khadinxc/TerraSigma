resource "azurerm_sentinel_alert_rule_scheduled" "permission_misconfiguration_reconnaissance_via_findstr_exe" {
  name                       = "permission_misconfiguration_reconnaissance_via_findstr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Permission Misconfiguration Reconnaissance Via Findstr.EXE"
  description                = "Detects usage of findstr with the \"EVERYONE\" or \"BUILTIN\" keywords. This was seen being used in combination with \"icacls\" and other utilities to spot misconfigured files or folders permissions."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "\"Everyone\"" or ProcessCommandLine contains "'Everyone'" or ProcessCommandLine contains "\"BUILTIN\\\"" or ProcessCommandLine contains "'BUILTIN\\'") and ((FolderPath endswith "\\find.exe" or FolderPath endswith "\\findstr.exe") or (ProcessVersionInfoOriginalFileName in~ ("FIND.EXE", "FINDSTR.EXE")))) or (ProcessCommandLine contains "icacls " and ProcessCommandLine contains "findstr " and ProcessCommandLine contains "Everyone")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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
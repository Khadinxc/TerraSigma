resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_use_of_psloglist" {
  name                       = "suspicious_use_of_psloglist"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Use of PsLogList"
  description                = "Detects usage of the PsLogList utility to dump event log in order to extract admin accounts and perform account discovery or delete events logs - Another tool that uses the command line switches of PsLogList - Legitimate use of PsLogList by an administrator"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " security" or ProcessCommandLine contains " application" or ProcessCommandLine contains " system") and (ProcessCommandLine contains " -d" or ProcessCommandLine contains " /d" or ProcessCommandLine contains " –d" or ProcessCommandLine contains " —d" or ProcessCommandLine contains " ―d" or ProcessCommandLine contains " -x" or ProcessCommandLine contains " /x" or ProcessCommandLine contains " –x" or ProcessCommandLine contains " —x" or ProcessCommandLine contains " ―x" or ProcessCommandLine contains " -s" or ProcessCommandLine contains " /s" or ProcessCommandLine contains " –s" or ProcessCommandLine contains " —s" or ProcessCommandLine contains " ―s" or ProcessCommandLine contains " -c" or ProcessCommandLine contains " /c" or ProcessCommandLine contains " –c" or ProcessCommandLine contains " —c" or ProcessCommandLine contains " ―c" or ProcessCommandLine contains " -g" or ProcessCommandLine contains " /g" or ProcessCommandLine contains " –g" or ProcessCommandLine contains " —g" or ProcessCommandLine contains " ―g") and (ProcessVersionInfoOriginalFileName =~ "psloglist.exe" or (FolderPath endswith "\\psloglist.exe" or FolderPath endswith "\\psloglist64.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1087"]
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
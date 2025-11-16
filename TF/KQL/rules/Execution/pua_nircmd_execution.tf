resource "azurerm_sentinel_alert_rule_scheduled" "pua_nircmd_execution" {
  name                       = "pua_nircmd_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - NirCmd Execution"
  description                = "Detects the use of NirCmd tool for command execution, which could be the result of legitimate administrative activity - Legitimate use by administrators"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " execmd " or ProcessCommandLine contains ".exe script " or ProcessCommandLine contains ".exe shexec " or ProcessCommandLine contains " runinteractive ") or (FolderPath endswith "\\NirCmd.exe" or ProcessVersionInfoOriginalFileName =~ "NirCmd.exe")) or ((ProcessCommandLine contains " exec " or ProcessCommandLine contains " exec2 ") and (ProcessCommandLine contains " show " or ProcessCommandLine contains " hide "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1569"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "net_exe_execution" {
  name                       = "net_exe_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Net.EXE Execution"
  description                = "Detects execution of \"Net.EXE\". - Likely"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " accounts" or ProcessCommandLine contains " group" or ProcessCommandLine contains " localgroup" or ProcessCommandLine contains " share" or ProcessCommandLine contains " start" or ProcessCommandLine contains " stop " or ProcessCommandLine contains " user" or ProcessCommandLine contains " view") and ((FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe") or (ProcessVersionInfoOriginalFileName in~ ("net.exe", "net1.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery", "LateralMovement"]
  techniques                 = ["T1007", "T1049", "T1018", "T1135", "T1201", "T1069", "T1087", "T1021"]
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
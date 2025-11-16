resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_extrac32_execution" {
  name                       = "suspicious_extrac32_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Extrac32 Execution"
  description                = "Download or Copy file with Extrac32"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains ".cab" and (ProcessCommandLine contains "extrac32.exe" or FolderPath endswith "\\extrac32.exe" or ProcessVersionInfoOriginalFileName =~ "extrac32.exe") and (ProcessCommandLine contains "/C" or ProcessCommandLine contains "/Y" or ProcessCommandLine contains " \\\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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
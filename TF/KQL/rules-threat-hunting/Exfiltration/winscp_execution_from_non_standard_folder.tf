resource "azurerm_sentinel_alert_rule_scheduled" "winscp_execution_from_non_standard_folder" {
  name                       = "winscp_execution_from_non_standard_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Winscp Execution From Non Standard Folder"
  description                = "Detects the execution of Winscp from an a non standard folder. This could indicate the execution of Winscp portable."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\WinSCP.exe" or ProcessVersionInfoOriginalFileName =~ "winscp.exe") and (not(FolderPath startswith "C:\\Program Files (x86)\\WinSCP\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1048"]
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
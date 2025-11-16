resource "azurerm_sentinel_alert_rule_scheduled" "driverquery_exe_execution" {
  name                       = "driverquery_exe_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DriverQuery.EXE Execution"
  description                = "Detect usage of the \"driverquery\" utility. Which can be used to perform reconnaissance on installed drivers - Legitimate use by third party tools in order to investigate installed drivers"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "driverquery.exe" or ProcessVersionInfoOriginalFileName =~ "drvqry.exe") and (not(((InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\regsvr32.exe" or InitiatingProcessFolderPath endswith "\\rundll32.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe") or (InitiatingProcessFolderPath contains "\\AppData\\Local\\" or InitiatingProcessFolderPath contains "\\Users\\Public\\" or InitiatingProcessFolderPath contains "\\Windows\\Temp\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
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
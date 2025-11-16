resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_pchunter_execution" {
  name                       = "hacktool_pchunter_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - PCHunter Execution"
  description                = "Detects suspicious use of PCHunter, a tool like Process Hacker to view and manipulate processes, kernel options and other low level stuff - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((SHA1 startswith "5F1CBC3D99558307BC1250D084FA968521482025" or SHA1 startswith "3FB89787CB97D902780DA080545584D97FB1C2EB") or (MD5 startswith "987B65CD9B9F4E9A1AFD8F8B48CF64A7" or MD5 startswith "228DD0C2E6287547E26FFBD973A40F14") or (SHA256 startswith "2B214BDDAAB130C274DE6204AF6DBA5AEEC7433DA99AA950022FA306421A6D32" or SHA256 startswith "55F041BF4E78E9BFA6D4EE68BE40E496CE3A1353E1CA4306598589E19802522C")) or (FolderPath endswith "\\PCHunter64.exe" or FolderPath endswith "\\PCHunter32.exe") or (ProcessVersionInfoOriginalFileName =~ "PCHunter.exe" or ProcessVersionInfoFileDescription =~ "Epoolsoft Windows Information View Tools")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Discovery"]
  techniques                 = ["T1082", "T1057", "T1012", "T1083", "T1007"]
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
    field_mapping {
      identifier  = "SHA1"
      column_name = "SHA1"
    }
    field_mapping {
      identifier  = "SHA256"
      column_name = "SHA256"
    }
    field_mapping {
      identifier  = "MD5"
      column_name = "MD5"
    }
  }
}
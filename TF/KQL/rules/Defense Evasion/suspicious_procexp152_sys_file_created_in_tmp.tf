resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_procexp152_sys_file_created_in_tmp" {
  name                       = "suspicious_procexp152_sys_file_created_in_tmp"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious PROCEXP152.sys File Created In TMP"
  description                = "Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder. This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU. - Other legimate tools using this driver and filename (like Sysinternals). Note - Clever attackers may easily bypass this detection by just renaming the driver filename. Therefore just Medium-level and don't rely on it."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "\\AppData\\Local\\Temp\\" and FolderPath endswith "PROCEXP152.sys") and (not((InitiatingProcessFolderPath contains "\\procexp64.exe" or InitiatingProcessFolderPath contains "\\procexp.exe" or InitiatingProcessFolderPath contains "\\procmon64.exe" or InitiatingProcessFolderPath contains "\\procmon.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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
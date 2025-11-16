resource "azurerm_sentinel_alert_rule_scheduled" "potential_dll_sideloading_of_dbgcore_dll" {
  name                       = "potential_dll_sideloading_of_dbgcore_dll"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential DLL Sideloading Of DBGCORE.DLL"
  description                = "Detects DLL sideloading of \"dbgcore.dll\" - Legitimate applications loading their own versions of the DLL mentioned in this rule"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\dbgcore.dll" and (not((FolderPath startswith "C:\\Program Files (x86)\\" or FolderPath startswith "C:\\Program Files\\" or FolderPath startswith "C:\\Windows\\SoftwareDistribution\\" or FolderPath startswith "C:\\Windows\\System32\\" or FolderPath startswith "C:\\Windows\\SystemTemp\\" or FolderPath startswith "C:\\Windows\\SysWOW64\\" or FolderPath startswith "C:\\Windows\\WinSxS\\"))) and (not(((FolderPath contains "opera\\Opera Installer Temp\\opera_package" and FolderPath endswith "\\assistant\\dbgcore.dll") or FolderPath endswith "\\Steam\\bin\\cef\\cef.win7x64\\dbgcore.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1574"]
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
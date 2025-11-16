resource "azurerm_sentinel_alert_rule_scheduled" "potential_mpclient_dll_sideloading" {
  name                       = "potential_mpclient_dll_sideloading"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Mpclient.DLL Sideloading"
  description                = "Detects potential sideloading of \"mpclient.dll\" by Windows Defender processes (\"MpCmdRun\" and \"NisSrv\") from their non-default directory. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\mpclient.dll" and (InitiatingProcessFolderPath endswith "\\MpCmdRun.exe" or InitiatingProcessFolderPath endswith "\\NisSrv.exe")) and (not((InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Windows Defender\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft Security Client\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Windows Defender\\" or InitiatingProcessFolderPath startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\WinSxS\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "DefenseEvasion"]
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
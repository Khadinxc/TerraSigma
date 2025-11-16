resource "azurerm_sentinel_alert_rule_scheduled" "aruba_network_service_potential_dll_sideloading" {
  name                       = "aruba_network_service_potential_dll_sideloading"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Aruba Network Service Potential DLL Sideloading"
  description                = "Detects potential DLL sideloading activity via the Aruba Networks Virtual Intranet Access \"arubanetsvc.exe\" process using DLL Search Order Hijacking"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where ((FolderPath endswith "\\wtsapi32.dll" or FolderPath endswith "\\msvcr100.dll" or FolderPath endswith "\\msvcp100.dll" or FolderPath endswith "\\dbghelp.dll" or FolderPath endswith "\\dbgcore.dll" or FolderPath endswith "\\wininet.dll" or FolderPath endswith "\\iphlpapi.dll" or FolderPath endswith "\\version.dll" or FolderPath endswith "\\cryptsp.dll" or FolderPath endswith "\\cryptbase.dll" or FolderPath endswith "\\wldp.dll" or FolderPath endswith "\\profapi.dll" or FolderPath endswith "\\sspicli.dll" or FolderPath endswith "\\winsta.dll" or FolderPath endswith "\\dpapi.dll") and InitiatingProcessFolderPath endswith "\\arubanetsvc.exe") and (not((FolderPath startswith "C:\\Windows\\System32\\" or FolderPath startswith "C:\\Windows\\SysWOW64\\" or FolderPath startswith "C:\\Windows\\WinSxS\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation", "Persistence"]
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
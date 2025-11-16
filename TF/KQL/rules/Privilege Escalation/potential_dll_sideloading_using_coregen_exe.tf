resource "azurerm_sentinel_alert_rule_scheduled" "potential_dll_sideloading_using_coregen_exe" {
  name                       = "potential_dll_sideloading_using_coregen_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential DLL Sideloading Using Coregen.exe"
  description                = "Detect usage of the \"coregen.exe\" (Microsoft CoreCLR Native Image Generator) binary to sideload arbitrary DLLs."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where InitiatingProcessFolderPath endswith "\\coregen.exe" and (not((FolderPath startswith "C:\\Program Files (x86)\\Microsoft Silverlight\\" or FolderPath startswith "C:\\Program Files\\Microsoft Silverlight\\" or FolderPath startswith "C:\\Windows\\System32\\" or FolderPath startswith "C:\\Windows\\SysWOW64\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1218", "T1055"]
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
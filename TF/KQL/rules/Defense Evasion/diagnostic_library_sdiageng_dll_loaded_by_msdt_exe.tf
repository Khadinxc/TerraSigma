resource "azurerm_sentinel_alert_rule_scheduled" "diagnostic_library_sdiageng_dll_loaded_by_msdt_exe" {
  name                       = "diagnostic_library_sdiageng_dll_loaded_by_msdt_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Diagnostic Library Sdiageng.DLL Loaded By Msdt.EXE"
  description                = "Detects both of CVE-2022-30190 (Follina) and DogWalk vulnerabilities exploiting msdt.exe binary to load the \"sdiageng.dll\" library"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\sdiageng.dll" and InitiatingProcessFolderPath endswith "\\msdt.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1202"]
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
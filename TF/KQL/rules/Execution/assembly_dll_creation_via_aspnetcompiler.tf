resource "azurerm_sentinel_alert_rule_scheduled" "assembly_dll_creation_via_aspnetcompiler" {
  name                       = "assembly_dll_creation_via_aspnetcompiler"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Assembly DLL Creation Via AspNetCompiler"
  description                = "Detects the creation of new DLL assembly files by \"aspnet_compiler.exe\", which could be a sign of \"aspnet_compiler\" abuse to proxy execution through a build provider. - Legitimate assembly compilation using a build provider"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\aspnet_compiler.exe" and (FolderPath contains "\\Temporary ASP.NET Files\\" and FolderPath contains "\\assembly\\tmp\\" and FolderPath contains ".dll")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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
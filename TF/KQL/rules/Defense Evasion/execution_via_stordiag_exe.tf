resource "azurerm_sentinel_alert_rule_scheduled" "execution_via_stordiag_exe" {
  name                       = "execution_via_stordiag_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Execution via stordiag.exe"
  description                = "Detects the use of stordiag.exe to execute schtasks.exe systeminfo.exe and fltmc.exe - Legitimate usage of stordiag.exe."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\systeminfo.exe" or FolderPath endswith "\\fltmc.exe") and InitiatingProcessFolderPath endswith "\\stordiag.exe") and (not((InitiatingProcessFolderPath startswith "c:\\windows\\system32\\" or InitiatingProcessFolderPath startswith "c:\\windows\\syswow64\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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
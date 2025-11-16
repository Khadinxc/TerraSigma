resource "azurerm_sentinel_alert_rule_scheduled" "uac_bypass_using_idiagnostic_profile_file" {
  name                       = "uac_bypass_using_idiagnostic_profile_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Bypass Using IDiagnostic Profile - File"
  description                = "Detects the creation of a file by \"dllhost.exe\" in System32 directory part of \"IDiagnosticProfileUAC\" UAC bypass technique"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\DllHost.exe" and FolderPath endswith ".dll" and FolderPath startswith "C:\\Windows\\System32\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "invocation_of_active_directory_diagnostic_tool_ntdsutil_exe" {
  name                       = "invocation_of_active_directory_diagnostic_tool_ntdsutil_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)"
  description                = "Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT) - NTDS maintenance"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\ntdsutil.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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
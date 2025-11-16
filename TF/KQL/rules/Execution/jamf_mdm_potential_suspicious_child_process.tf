resource "azurerm_sentinel_alert_rule_scheduled" "jamf_mdm_potential_suspicious_child_process" {
  name                       = "jamf_mdm_potential_suspicious_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "JAMF MDM Potential Suspicious Child Process"
  description                = "Detects potential suspicious child processes of \"jamf\". Could be a sign of potential abuse of Jamf as a C2 server as seen by Typhon MythicAgent. - Legitimate execution of custom scripts or commands by Jamf administrators. Apply additional filters accordingly"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "/bash" or FolderPath endswith "/sh") and InitiatingProcessFolderPath endswith "/jamf"
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
resource "azurerm_sentinel_alert_rule_scheduled" "persistence_via_sudoers_files" {
  name                       = "persistence_via_sudoers_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Persistence Via Sudoers Files"
  description                = "Detects creation of sudoers file or files in \"sudoers.d\" directory which can be used a potential method to persiste privileges for a specific user. - Creation of legitimate files in sudoers.d folder part of administrator work"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath startswith "/etc/sudoers.d/"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
  techniques                 = ["T1053"]
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
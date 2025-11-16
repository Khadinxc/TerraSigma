resource "azurerm_sentinel_alert_rule_scheduled" "indirect_command_execution_by_program_compatibility_wizard" {
  name                       = "indirect_command_execution_by_program_compatibility_wizard"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Indirect Command Execution By Program Compatibility Wizard"
  description                = "Detect indirect command execution via Program Compatibility Assistant pcwrun.exe - Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts - Legit usage of scripts"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\pcwrun.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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
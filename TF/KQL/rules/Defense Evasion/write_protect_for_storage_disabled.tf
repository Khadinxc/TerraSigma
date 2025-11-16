resource "azurerm_sentinel_alert_rule_scheduled" "write_protect_for_storage_disabled" {
  name                       = "write_protect_for_storage_disabled"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Write Protect For Storage Disabled"
  description                = "Detects applications trying to modify the registry in order to disable any write-protect property for storage devices. This could be a precursor to a ransomware attack and has been an observed technique used by cypherpunk group."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\\System\\CurrentControlSet\\Control" and ProcessCommandLine contains "Write Protection" and ProcessCommandLine contains "0" and ProcessCommandLine contains "storage"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}
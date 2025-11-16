resource "azurerm_sentinel_alert_rule_scheduled" "start_of_nt_virtual_dos_machine" {
  name                       = "start_of_nt_virtual_dos_machine"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Start of NT Virtual DOS Machine"
  description                = "Ntvdm.exe allows the execution of 16-bit Windows applications on 32-bit Windows operating systems, as well as the execution of both 16-bit and 32-bit DOS applications - Legitimate use"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\ntvdm.exe" or FolderPath endswith "\\csrstub.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
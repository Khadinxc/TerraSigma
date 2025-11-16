resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_creation_with_colorcpl" {
  name                       = "suspicious_creation_with_colorcpl"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Creation with Colorcpl"
  description                = "Once executed, colorcpl.exe will copy the arbitrary file to c:\\windows\\system32\\spool\\drivers\\color\\"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\colorcpl.exe" and (not((FolderPath endswith ".icm" or FolderPath endswith ".gmmp" or FolderPath endswith ".cdmp" or FolderPath endswith ".camp")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1564"]
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
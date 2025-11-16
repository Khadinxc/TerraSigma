resource "azurerm_sentinel_alert_rule_scheduled" "unattend_xml_file_access_attempt" {
  name                       = "unattend_xml_file_access_attempt"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Unattend.XML File Access Attempt"
  description                = "Detects attempts to access the \"unattend.xml\" file, where credentials might be stored. This file is used during the unattended windows install process."
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where FileName endswith "\\Panther\\unattend.xml"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
  }
}
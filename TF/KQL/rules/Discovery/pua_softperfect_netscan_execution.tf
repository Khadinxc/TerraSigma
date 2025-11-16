resource "azurerm_sentinel_alert_rule_scheduled" "pua_softperfect_netscan_execution" {
  name                       = "pua_softperfect_netscan_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - SoftPerfect Netscan Execution"
  description                = "Detects usage of SoftPerfect's \"netscan.exe\". An application for scanning networks. It is actively used in-the-wild by threat actors to inspect and understand the network architecture of a victim. - Legitimate administrator activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\netscan.exe" or ProcessVersionInfoProductName =~ "Network Scanner" or ProcessVersionInfoFileDescription =~ "Application for scanning networks"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1046"]
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
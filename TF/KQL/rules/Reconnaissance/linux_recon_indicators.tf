resource "azurerm_sentinel_alert_rule_scheduled" "linux_recon_indicators" {
  name                       = "linux_recon_indicators"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Linux Recon Indicators"
  description                = "Detects events with patterns found in commands used for reconnaissance on linux systems - Legitimate administration activities"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " -name .htpasswd" or ProcessCommandLine contains " -perm -4000 "
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Reconnaissance", "CredentialAccess"]
  techniques                 = ["T1592", "T1552"]
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
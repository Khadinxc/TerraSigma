resource "azurerm_sentinel_alert_rule_scheduled" "forest_blizzard_apt_javascript_constrained_file_creation" {
  name                       = "forest_blizzard_apt_javascript_constrained_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Forest Blizzard APT - JavaScript Constrained File Creation"
  description                = "Detects the creation of JavaScript files inside of the DriverStore directory. Forest Blizzard used this to exploit the CVE-2022-38028 vulnerability in Windows Print Spooler service by modifying a JavaScript constraints file and executing it with SYSTEM-level permissions. - Unlikely"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\.js" and FolderPath startswith "C:\\Windows\\System32\\DriverStore\\FileRepository\\"
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
resource "azurerm_sentinel_alert_rule_scheduled" "cloudflared_portable_execution" {
  name                       = "cloudflared_portable_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Cloudflared Portable Execution"
  description                = "Detects the execution of the \"cloudflared\" binary from a non standard location. - Legitimate usage of Cloudflared portable versions"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\cloudflared.exe" and (not((FolderPath contains ":\\Program Files (x86)\\cloudflared\\" or FolderPath contains ":\\Program Files\\cloudflared\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1090"]
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
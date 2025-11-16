resource "azurerm_sentinel_alert_rule_scheduled" "trustedpath_uac_bypass_pattern" {
  name                       = "trustedpath_uac_bypass_pattern"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "TrustedPath UAC Bypass Pattern"
  description                = "Detects indicators of a UAC bypass method by mocking directories"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath contains "C:\\Windows \\System32\\" or FolderPath contains "C:\\Windows \\SysWOW64\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1548"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_iis_module_registration" {
  name                       = "suspicious_iis_module_registration"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious IIS Module Registration"
  description                = "Detects a suspicious IIS module registration as described in Microsoft threat report on IIS backdoors - Administrative activity"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\w3wp.exe" and (ProcessCommandLine contains "appcmd.exe add module" or (ProcessCommandLine contains " system.enterpriseservices.internal.publish" and FolderPath endswith "\\powershell.exe") or (ProcessCommandLine contains "gacutil" and ProcessCommandLine contains " /I"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1505"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "pua_advanced_ip_scanner_execution" {
  name                       = "pua_advanced_ip_scanner_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Advanced IP Scanner Execution"
  description                = "Detects the use of Advanced IP Scanner. Seems to be a popular tool for ransomware groups. - Legitimate administrative use"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/portable" and ProcessCommandLine contains "/lng") or (FolderPath contains "\\advanced_ip_scanner" or ProcessVersionInfoOriginalFileName contains "advanced_ip_scanner" or ProcessVersionInfoFileDescription contains "Advanced IP Scanner")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1046", "T1135"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
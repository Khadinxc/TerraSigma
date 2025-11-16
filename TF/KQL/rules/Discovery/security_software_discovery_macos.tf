resource "azurerm_sentinel_alert_rule_scheduled" "security_software_discovery_macos" {
  name                       = "security_software_discovery_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Security Software Discovery - MacOs"
  description                = "Detects usage of system utilities (only grep for now) to discover security software discovery - Legitimate activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath =~ "/usr/bin/grep" and ((ProcessCommandLine contains "nessusd" or ProcessCommandLine contains "santad" or ProcessCommandLine contains "CbDefense" or ProcessCommandLine contains "falcond" or ProcessCommandLine contains "td-agent" or ProcessCommandLine contains "packetbeat" or ProcessCommandLine contains "filebeat" or ProcessCommandLine contains "auditbeat" or ProcessCommandLine contains "osqueryd" or ProcessCommandLine contains "BlockBlock" or ProcessCommandLine contains "LuLu") or (ProcessCommandLine contains "Little" and ProcessCommandLine contains "Snitch"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1518"]
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
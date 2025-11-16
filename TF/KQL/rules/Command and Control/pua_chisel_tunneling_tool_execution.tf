resource "azurerm_sentinel_alert_rule_scheduled" "pua_chisel_tunneling_tool_execution" {
  name                       = "pua_chisel_tunneling_tool_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Chisel Tunneling Tool Execution"
  description                = "Detects usage of the Chisel tunneling tool via the commandline arguments - Some false positives may occur with other tools with similar commandlines"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\chisel.exe" or ((ProcessCommandLine contains "exe client " or ProcessCommandLine contains "exe server ") and (ProcessCommandLine contains "-socks5" or ProcessCommandLine contains "-reverse" or ProcessCommandLine contains " r:" or ProcessCommandLine contains ":127.0.0.1:" or ProcessCommandLine contains "-tls-skip-verify " or ProcessCommandLine contains ":socks"))
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
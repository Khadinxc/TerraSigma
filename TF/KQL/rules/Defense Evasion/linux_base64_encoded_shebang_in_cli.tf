resource "azurerm_sentinel_alert_rule_scheduled" "linux_base64_encoded_shebang_in_cli" {
  name                       = "linux_base64_encoded_shebang_in_cli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Linux Base64 Encoded Shebang In CLI"
  description                = "Detects the presence of a base64 version of the shebang in the commandline, which could indicate a malicious payload about to be decoded - Legitimate administration activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "IyEvYmluL2Jhc2" or ProcessCommandLine contains "IyEvYmluL2Rhc2" or ProcessCommandLine contains "IyEvYmluL3pza" or ProcessCommandLine contains "IyEvYmluL2Zpc2" or ProcessCommandLine contains "IyEvYmluL3No"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1140"]
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
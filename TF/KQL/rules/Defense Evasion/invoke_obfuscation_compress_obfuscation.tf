resource "azurerm_sentinel_alert_rule_scheduled" "invoke_obfuscation_compress_obfuscation" {
  name                       = "invoke_obfuscation_compress_obfuscation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Invoke-Obfuscation COMPRESS OBFUSCATION"
  description                = "Detects Obfuscated Powershell via COMPRESS OBFUSCATION"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "system.io.compression.deflatestream" or ProcessCommandLine contains "system.io.streamreader" or ProcessCommandLine contains "readtoend(") and (ProcessCommandLine contains "new-object" and ProcessCommandLine contains "text.encoding]::ascii")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1027", "T1059"]
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
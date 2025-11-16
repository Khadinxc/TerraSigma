resource "azurerm_sentinel_alert_rule_scheduled" "invoke_obfuscation_via_use_mshta" {
  name                       = "invoke_obfuscation_via_use_mshta"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Invoke-Obfuscation Via Use MSHTA"
  description                = "Detects Obfuscated Powershell via use MSHTA in Scripts"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "set" and ProcessCommandLine contains "&&" and ProcessCommandLine contains "mshta" and ProcessCommandLine contains "vbscript:createobject" and ProcessCommandLine contains ".run" and ProcessCommandLine contains "(window.close)"
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
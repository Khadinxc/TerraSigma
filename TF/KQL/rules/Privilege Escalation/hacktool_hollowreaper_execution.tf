resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_hollowreaper_execution" {
  name                       = "hacktool_hollowreaper_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - HollowReaper Execution"
  description                = "Detects usage of HollowReaper, a process hollowing shellcode launcher used for stealth payload execution through process hollowing. It replaces the memory of a legitimate process with custom shellcode, allowing the attacker to execute payloads under the guise of trusted binaries."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\HollowReaper.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1055"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "ursnif_redirection_of_discovery_commands" {
  name                       = "ursnif_redirection_of_discovery_commands"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Ursnif Redirection Of Discovery Commands"
  description                = "Detects the redirection of Ursnif discovery commands as part of the initial execution of the malware. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/C " and (ProcessCommandLine contains " >> " and ProcessCommandLine contains "\\AppData\\local\\temp*.bin")) and FolderPath endswith "\\cmd.exe" and InitiatingProcessFolderPath endswith "\\explorer.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
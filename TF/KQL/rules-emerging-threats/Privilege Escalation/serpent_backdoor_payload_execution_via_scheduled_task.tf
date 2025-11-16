resource "azurerm_sentinel_alert_rule_scheduled" "serpent_backdoor_payload_execution_via_scheduled_task" {
  name                       = "serpent_backdoor_payload_execution_via_scheduled_task"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Serpent Backdoor Payload Execution Via Scheduled Task"
  description                = "Detects post exploitation execution technique of the Serpent backdoor. According to Proofpoint, one of the commands that the backdoor ran was via creating a temporary scheduled task using an unusual method. It creates a fictitious windows event and a trigger in which once the event is created, it executes the payload. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "[System/EventID=" and ProcessCommandLine contains "/create" and ProcessCommandLine contains "/delete" and ProcessCommandLine contains "/ec" and ProcessCommandLine contains "/so" and ProcessCommandLine contains "/tn run") and (FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\powershell.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
  techniques                 = ["T1053", "T1059"]
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
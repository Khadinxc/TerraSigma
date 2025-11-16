resource "azurerm_sentinel_alert_rule_scheduled" "raspberry_robin_initial_execution_from_external_drive" {
  name                       = "raspberry_robin_initial_execution_from_external_drive"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Raspberry Robin Initial Execution From External Drive"
  description                = "Detects the initial execution of the Raspberry Robin malware from an external drive using \"Cmd.EXE\". - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "http:" or ProcessCommandLine contains "https:") and ((ProcessCommandLine contains "-q" or ProcessCommandLine contains "/q" or ProcessCommandLine contains "–q" or ProcessCommandLine contains "—q" or ProcessCommandLine contains "―q") and FolderPath endswith "\\msiexec.exe") and (InitiatingProcessCommandLine contains "/r" and (InitiatingProcessCommandLine endswith ".bin" or InitiatingProcessCommandLine endswith ".ico" or InitiatingProcessCommandLine endswith ".lnk" or InitiatingProcessCommandLine endswith ".lo" or InitiatingProcessCommandLine endswith ".sv" or InitiatingProcessCommandLine endswith ".usb") and InitiatingProcessFolderPath endswith "\\cmd.exe")
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
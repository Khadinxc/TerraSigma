resource "azurerm_sentinel_alert_rule_scheduled" "elise_backdoor_activity" {
  name                       = "elise_backdoor_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Elise Backdoor Activity"
  description                = "Detects Elise backdoor activity used by APT32 - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "\\Windows\\Caches\\NavShExt.dll" and ProcessCommandLine contains "/c del") or FolderPath endswith "\\Microsoft\\Network\\svchost.exe") or (ProcessCommandLine contains ",Setting" and (ProcessCommandLine endswith "\\AppData\\Roaming\\MICROS~1\\Windows\\Caches\\NavShExt.dll" or ProcessCommandLine endswith "\\AppData\\Roaming\\Microsoft\\Windows\\Caches\\NavShExt.dll"))
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
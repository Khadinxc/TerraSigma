resource "azurerm_sentinel_alert_rule_scheduled" "arbitrary_file_download_via_squirrel_exe" {
  name                       = "arbitrary_file_download_via_squirrel_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Arbitrary File Download Via Squirrel.EXE"
  description                = "Detects the usage of the \"Squirrel.exe\" to download arbitrary files. This binary is part of multiple Electron based software installations (Slack, Teams, Discord, etc.) - Expected FP with some Electron based applications such as (1Clipboard, Beaker Browser, Caret, Discord, GitHub Desktop, etc.)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " --download " or ProcessCommandLine contains " --update " or ProcessCommandLine contains " --updateRollback=") and ProcessCommandLine contains "http" and (FolderPath endswith "\\squirrel.exe" or FolderPath endswith "\\update.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1218"]
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
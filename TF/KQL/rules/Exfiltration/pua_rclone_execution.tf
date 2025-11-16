resource "azurerm_sentinel_alert_rule_scheduled" "pua_rclone_execution" {
  name                       = "pua_rclone_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Rclone Execution"
  description                = "Detects execution of RClone utility for exfiltration as used by various ransomwares strains like REvil, Conti, FiveHands, etc"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "--config " and ProcessCommandLine contains "--no-check-certificate " and ProcessCommandLine contains " copy ") or ((ProcessCommandLine contains "pass" or ProcessCommandLine contains "user" or ProcessCommandLine contains "copy" or ProcessCommandLine contains "sync" or ProcessCommandLine contains "config" or ProcessCommandLine contains "lsd" or ProcessCommandLine contains "remote" or ProcessCommandLine contains "ls" or ProcessCommandLine contains "mega" or ProcessCommandLine contains "pcloud" or ProcessCommandLine contains "ftp" or ProcessCommandLine contains "ignore-existing" or ProcessCommandLine contains "auto-confirm" or ProcessCommandLine contains "transfers" or ProcessCommandLine contains "multi-thread-streams" or ProcessCommandLine contains "no-check-certificate ") and (FolderPath endswith "\\rclone.exe" or ProcessVersionInfoFileDescription =~ "Rsync for cloud storage"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1567"]
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
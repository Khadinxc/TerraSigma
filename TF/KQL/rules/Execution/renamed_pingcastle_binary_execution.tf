resource "azurerm_sentinel_alert_rule_scheduled" "renamed_pingcastle_binary_execution" {
  name                       = "renamed_pingcastle_binary_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Renamed PingCastle Binary Execution"
  description                = "Detects the execution of a renamed \"PingCastle\" binary based on the PE metadata fields."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessVersionInfoOriginalFileName in~ ("PingCastleReporting.exe", "PingCastleCloud.exe", "PingCastle.exe")) or (ProcessCommandLine contains "--scanner aclcheck" or ProcessCommandLine contains "--scanner antivirus" or ProcessCommandLine contains "--scanner computerversion" or ProcessCommandLine contains "--scanner foreignusers" or ProcessCommandLine contains "--scanner laps_bitlocker" or ProcessCommandLine contains "--scanner localadmin" or ProcessCommandLine contains "--scanner nullsession" or ProcessCommandLine contains "--scanner nullsession-trust" or ProcessCommandLine contains "--scanner oxidbindings" or ProcessCommandLine contains "--scanner remote" or ProcessCommandLine contains "--scanner share" or ProcessCommandLine contains "--scanner smb" or ProcessCommandLine contains "--scanner smb3querynetwork" or ProcessCommandLine contains "--scanner spooler" or ProcessCommandLine contains "--scanner startup" or ProcessCommandLine contains "--scanner zerologon") or ProcessCommandLine contains "--no-enum-limit" or (ProcessCommandLine contains "--healthcheck" and ProcessCommandLine contains "--level Full") or (ProcessCommandLine contains "--healthcheck" and ProcessCommandLine contains "--server ")) and (not((FolderPath endswith "\\PingCastleReporting.exe" or FolderPath endswith "\\PingCastleCloud.exe" or FolderPath endswith "\\PingCastle.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1059", "T1202"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
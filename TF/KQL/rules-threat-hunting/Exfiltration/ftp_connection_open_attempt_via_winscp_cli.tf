resource "azurerm_sentinel_alert_rule_scheduled" "ftp_connection_open_attempt_via_winscp_cli" {
  name                       = "ftp_connection_open_attempt_via_winscp_cli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "FTP Connection Open Attempt Via Winscp CLI"
  description                = "Detects the execution of Winscp with the \"-command\" and the \"open\" flags in order to open an FTP connection. Akira ransomware was seen using this technique in order to exfiltrate data."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "open " and ProcessCommandLine contains "ftp://") and (ProcessCommandLine contains "-command" or ProcessCommandLine contains "/command" or ProcessCommandLine contains "–command" or ProcessCommandLine contains "—command" or ProcessCommandLine contains "―command")) and (FolderPath endswith "\\WinSCP.exe" or ProcessVersionInfoOriginalFileName =~ "winscp.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1048"]
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
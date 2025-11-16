resource "azurerm_sentinel_alert_rule_scheduled" "new_remote_desktop_connection_initiated_via_mstsc_exe" {
  name                       = "new_remote_desktop_connection_initiated_via_mstsc_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Remote Desktop Connection Initiated Via Mstsc.EXE"
  description                = "Detects the usage of \"mstsc.exe\" with the \"/v\" flag to initiate a connection to a remote server. Adversaries may use valid accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user. - WSL (Windows Sub System For Linux)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -v:" or ProcessCommandLine contains " /v:" or ProcessCommandLine contains " –v:" or ProcessCommandLine contains " —v:" or ProcessCommandLine contains " ―v:") and (FolderPath endswith "\\mstsc.exe" or ProcessVersionInfoOriginalFileName =~ "mstsc.exe")) and (not((ProcessCommandLine contains "C:\\ProgramData\\Microsoft\\WSL\\wslg.rdp" and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\lxss\\wslhost.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement"]
  techniques                 = ["T1021"]
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
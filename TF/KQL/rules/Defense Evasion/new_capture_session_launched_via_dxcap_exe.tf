resource "azurerm_sentinel_alert_rule_scheduled" "new_capture_session_launched_via_dxcap_exe" {
  name                       = "new_capture_session_launched_via_dxcap_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Capture Session Launched Via DXCap.EXE"
  description                = "Detects the execution of \"DXCap.EXE\" with the \"-c\" flag, which allows a user to launch any arbitrary binary or windows package through DXCap itself. This can be abused to potentially bypass application whitelisting. - Legitimate execution of dxcap.exe by legitimate user"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " -c " and (FolderPath endswith "\\DXCap.exe" or ProcessVersionInfoOriginalFileName =~ "DXCap.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
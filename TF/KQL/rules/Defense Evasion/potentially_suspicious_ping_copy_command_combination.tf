resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_ping_copy_command_combination" {
  name                       = "potentially_suspicious_ping_copy_command_combination"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Ping/Copy Command Combination"
  description                = "Detects uncommon and potentially suspicious one-liner command containing both \"ping\" and \"copy\" at the same time, which is usually used by malware."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "ping" and ProcessCommandLine contains "copy ") and (ProcessCommandLine contains " -n " or ProcessCommandLine contains " /n " or ProcessCommandLine contains " –n " or ProcessCommandLine contains " —n " or ProcessCommandLine contains " ―n ") and (ProcessCommandLine contains " -y " or ProcessCommandLine contains " /y " or ProcessCommandLine contains " –y " or ProcessCommandLine contains " —y " or ProcessCommandLine contains " ―y ") and (FolderPath endswith "\\cmd.exe" or ProcessVersionInfoOriginalFileName =~ "Cmd.Exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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
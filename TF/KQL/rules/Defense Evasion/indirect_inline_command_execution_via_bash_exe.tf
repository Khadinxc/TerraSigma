resource "azurerm_sentinel_alert_rule_scheduled" "indirect_inline_command_execution_via_bash_exe" {
  name                       = "indirect_inline_command_execution_via_bash_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Indirect Inline Command Execution Via Bash.EXE"
  description                = "Detects execution of Microsoft bash launcher with the \"-c\" flag. This can be used to potentially bypass defenses and execute Linux or Windows-based binaries directly via bash."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " -c " and ((FolderPath endswith ":\\Windows\\System32\\bash.exe" or FolderPath endswith ":\\Windows\\SysWOW64\\bash.exe") or ProcessVersionInfoOriginalFileName =~ "Bash.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1202"]
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
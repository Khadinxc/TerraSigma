resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_userinit_child_process" {
  name                       = "suspicious_userinit_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Userinit Child Process"
  description                = "Detects a suspicious child process of userinit - Administrative scripts"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\userinit.exe" and (not(((FolderPath endswith "\\explorer.exe" or ProcessVersionInfoOriginalFileName =~ "explorer.exe" or ProcessCommandLine =~ "C:\\Windows\\Explorer.EXE") or ProcessCommandLine contains "\\netlogon\\" or isnull(FolderPath))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1055"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "direct_autorun_keys_modification" {
  name                       = "direct_autorun_keys_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Direct Autorun Keys Modification"
  description                = "Detects direct modification of autostart extensibility point (ASEP) in registry using reg.exe. - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reasons. - Legitimate administrator sets up autorun keys for legitimate reasons. - Discord"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "add" and (ProcessCommandLine contains "\\software\\Microsoft\\Windows\\CurrentVersion\\Run" or ProcessCommandLine contains "\\software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" or ProcessCommandLine contains "\\software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" or ProcessCommandLine contains "\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" or ProcessCommandLine contains "\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" or ProcessCommandLine contains "\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" or ProcessCommandLine contains "\\software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" or ProcessCommandLine contains "\\system\\CurrentControlSet\\Control\\SafeBoot\\AlternateShell") and (FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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
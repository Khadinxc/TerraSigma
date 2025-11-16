resource "azurerm_sentinel_alert_rule_scheduled" "wsl_kali_linux_usage" {
  name                       = "wsl_kali_linux_usage"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WSL Kali-Linux Usage"
  description                = "Detects the use of Kali Linux through Windows Subsystem for Linux - Legitimate installation or usage of Kali Linux WSL by administrators or security teams"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((FolderPath contains ":\\Users\\" and FolderPath contains "\\AppData\\Local\\packages\\KaliLinux") or (FolderPath contains ":\\Users\\" and FolderPath contains "\\AppData\\Local\\Microsoft\\WindowsApps\\kali.exe")) or (FolderPath contains ":\\Program Files\\WindowsApps\\KaliLinux." and FolderPath endswith "\\kali.exe")) or ((((FolderPath contains "\\kali.exe" or FolderPath contains "\\KaliLinux") or (ProcessCommandLine contains "Kali.exe" or ProcessCommandLine contains "Kali-linux" or ProcessCommandLine contains "kalilinux")) and (InitiatingProcessFolderPath endswith "\\wsl.exe" or InitiatingProcessFolderPath endswith "\\wslhost.exe")) and (not((ProcessCommandLine contains " -i " or ProcessCommandLine contains " --install " or ProcessCommandLine contains " --unregister "))))
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
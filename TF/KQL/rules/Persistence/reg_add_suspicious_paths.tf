resource "azurerm_sentinel_alert_rule_scheduled" "reg_add_suspicious_paths" {
  name                       = "reg_add_suspicious_paths"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Reg Add Suspicious Paths"
  description                = "Detects when an adversary uses the reg.exe utility to add or modify new keys or subkeys - Rare legitimate add to registry via cli (to these locations)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\AppDataLow\\Software\\Microsoft\\" or ProcessCommandLine contains "\\Policies\\Microsoft\\Windows\\OOBE" or ProcessCommandLine contains "\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" or ProcessCommandLine contains "\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon" or ProcessCommandLine contains "\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" or ProcessCommandLine contains "\\Microsoft\\Windows Defender\\") and (FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112", "T1562"]
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
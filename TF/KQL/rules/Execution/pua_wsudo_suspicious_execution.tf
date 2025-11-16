resource "azurerm_sentinel_alert_rule_scheduled" "pua_wsudo_suspicious_execution" {
  name                       = "pua_wsudo_suspicious_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Wsudo Suspicious Execution"
  description                = "Detects usage of wsudo (Windows Sudo Utility). Which is a tool that let the user execute programs with different permissions (System, Trusted Installer, Administrator...etc)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-u System" or ProcessCommandLine contains "-uSystem" or ProcessCommandLine contains "-u TrustedInstaller" or ProcessCommandLine contains "-uTrustedInstaller" or ProcessCommandLine contains " --ti ") or (FolderPath endswith "\\wsudo.exe" or ProcessVersionInfoOriginalFileName =~ "wsudo.exe" or ProcessVersionInfoFileDescription =~ "Windows sudo utility" or InitiatingProcessFolderPath endswith "\\wsudo-bridge.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "PrivilegeEscalation"]
  techniques                 = ["T1059"]
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
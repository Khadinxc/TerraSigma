resource "azurerm_sentinel_alert_rule_scheduled" "powershell_web_access_feature_enabled_via_dism" {
  name                       = "powershell_web_access_feature_enabled_via_dism"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Web Access Feature Enabled Via DISM"
  description                = "Detects the use of DISM to enable the PowerShell Web Access feature, which could be used for remote access and potential abuse - Legitimate PowerShell Web Access installations by administrators"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "WindowsPowerShellWebAccess" and ProcessCommandLine contains "/online" and ProcessCommandLine contains "/enable-feature") and (FolderPath endswith "\\dism.exe" or ProcessVersionInfoOriginalFileName =~ "DISM.EXE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion", "Persistence"]
  techniques                 = ["T1548"]
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
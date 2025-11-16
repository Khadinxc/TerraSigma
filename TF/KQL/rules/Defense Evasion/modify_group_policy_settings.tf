resource "azurerm_sentinel_alert_rule_scheduled" "modify_group_policy_settings" {
  name                       = "modify_group_policy_settings"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Modify Group Policy Settings"
  description                = "Detect malicious GPO modifications can be used to implement many other malicious behaviors. - Legitimate use"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "GroupPolicyRefreshTimeDC" or ProcessCommandLine contains "GroupPolicyRefreshTimeOffsetDC" or ProcessCommandLine contains "GroupPolicyRefreshTime" or ProcessCommandLine contains "GroupPolicyRefreshTimeOffset" or ProcessCommandLine contains "EnableSmartScreen" or ProcessCommandLine contains "ShellSmartScreenLevel") and ProcessCommandLine contains "\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" and (FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1484"]
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
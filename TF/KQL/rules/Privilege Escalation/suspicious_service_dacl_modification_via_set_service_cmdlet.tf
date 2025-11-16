resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_service_dacl_modification_via_set_service_cmdlet" {
  name                       = "suspicious_service_dacl_modification_via_set_service_cmdlet"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Service DACL Modification Via Set-Service Cmdlet"
  description                = "Detects suspicious DACL modifications via the \"Set-Service\" cmdlet using the \"SecurityDescriptorSddl\" flag (Only available with PowerShell 7) that can be used to hide services or make them unstopable"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\pwsh.exe" or ProcessVersionInfoOriginalFileName =~ "pwsh.dll") and (ProcessCommandLine contains "-SecurityDescriptorSddl " or ProcessCommandLine contains "-sd ") and ((ProcessCommandLine contains ";;;IU" or ProcessCommandLine contains ";;;SU" or ProcessCommandLine contains ";;;BA" or ProcessCommandLine contains ";;;SY" or ProcessCommandLine contains ";;;WD") and (ProcessCommandLine contains "Set-Service " and ProcessCommandLine contains "D;;"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1543"]
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
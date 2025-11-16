resource "azurerm_sentinel_alert_rule_scheduled" "stop_windows_service_via_powershell_stop_service" {
  name                       = "stop_windows_service_via_powershell_stop_service"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Stop Windows Service Via PowerShell Stop-Service"
  description                = "Detects the stopping of a Windows service via the PowerShell Cmdlet \"Stop-Service\" - There are many legitimate reasons to stop a service. This rule isn't looking for any suspicious behaviour in particular. Filter legitimate activity accordingly"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "Stop-Service " and ((ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")) or (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1489"]
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
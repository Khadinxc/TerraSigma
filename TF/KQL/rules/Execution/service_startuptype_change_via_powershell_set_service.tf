resource "azurerm_sentinel_alert_rule_scheduled" "service_startuptype_change_via_powershell_set_service" {
  name                       = "service_startuptype_change_via_powershell_set_service"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Service StartupType Change Via PowerShell Set-Service"
  description                = "Detects the use of the PowerShell \"Set-Service\" cmdlet to change the startup type of a service to \"disabled\" or \"manual\""
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "Disabled" or ProcessCommandLine contains "Manual") and (ProcessCommandLine contains "Set-Service" and ProcessCommandLine contains "-StartupType")) and (FolderPath endswith "\\powershell.exe" or ProcessVersionInfoOriginalFileName =~ "PowerShell.EXE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1562"]
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
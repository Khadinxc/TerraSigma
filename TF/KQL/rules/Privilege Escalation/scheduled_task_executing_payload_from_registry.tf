resource "azurerm_sentinel_alert_rule_scheduled" "scheduled_task_executing_payload_from_registry" {
  name                       = "scheduled_task_executing_payload_from_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Scheduled Task Executing Payload from Registry"
  description                = "Detects the creation of a schtasks that potentially executes a payload stored in the Windows Registry using PowerShell."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/Create" and (ProcessCommandLine contains "Get-ItemProperty" or ProcessCommandLine contains " gp ") and (ProcessCommandLine contains "HKCU:" or ProcessCommandLine contains "HKLM:" or ProcessCommandLine contains "registry::" or ProcessCommandLine contains "HKEY_") and (FolderPath endswith "\\schtasks.exe" or ProcessVersionInfoOriginalFileName =~ "schtasks.exe")) and (not((ProcessCommandLine contains "FromBase64String" or ProcessCommandLine contains "encodedcommand")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
  techniques                 = ["T1053", "T1059"]
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
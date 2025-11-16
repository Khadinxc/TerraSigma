resource "azurerm_sentinel_alert_rule_scheduled" "recon_information_for_export_with_command_prompt" {
  name                       = "recon_information_for_export_with_command_prompt"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Recon Information for Export with Command Prompt"
  description                = "Once established within a system or network, an adversary may use automated techniques for collecting internal data."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\tree.com" or FolderPath endswith "\\WMIC.exe" or FolderPath endswith "\\doskey.exe" or FolderPath endswith "\\sc.exe") or (ProcessVersionInfoOriginalFileName in~ ("wmic.exe", "DOSKEY.EXE", "sc.exe"))) and (InitiatingProcessCommandLine contains " > %TEMP%\\" or InitiatingProcessCommandLine contains " > %TMP%\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1119"]
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
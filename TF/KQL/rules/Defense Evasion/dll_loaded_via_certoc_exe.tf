resource "azurerm_sentinel_alert_rule_scheduled" "dll_loaded_via_certoc_exe" {
  name                       = "dll_loaded_via_certoc_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DLL Loaded via CertOC.EXE"
  description                = "Detects when a user installs certificates by using CertOC.exe to loads the target DLL file."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -LoadDLL " or ProcessCommandLine contains " /LoadDLL " or ProcessCommandLine contains " –LoadDLL " or ProcessCommandLine contains " —LoadDLL " or ProcessCommandLine contains " ―LoadDLL ") and (FolderPath endswith "\\certoc.exe" or ProcessVersionInfoOriginalFileName =~ "CertOC.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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
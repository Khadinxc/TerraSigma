resource "azurerm_sentinel_alert_rule_scheduled" "potential_unquoted_service_path_reconnaissance_via_wmic_exe" {
  name                       = "potential_unquoted_service_path_reconnaissance_via_wmic_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Unquoted Service Path Reconnaissance Via Wmic.EXE"
  description                = "Detects known WMI recon method to look for unquoted service paths using wmic. Often used by pentester and attacker enumeration scripts"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " service get " and ProcessCommandLine contains "name,displayname,pathname,startmode") and (ProcessVersionInfoOriginalFileName =~ "wmic.exe" or FolderPath endswith "\\WMIC.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1047"]
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
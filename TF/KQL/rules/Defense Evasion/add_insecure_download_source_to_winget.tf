resource "azurerm_sentinel_alert_rule_scheduled" "add_insecure_download_source_to_winget" {
  name                       = "add_insecure_download_source_to_winget"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Add Insecure Download Source To Winget"
  description                = "Detects usage of winget to add a new insecure (http) download source. Winget will not allow the addition of insecure sources, hence this could indicate potential suspicious activity (or typos)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "source " and ProcessCommandLine contains "add " and ProcessCommandLine contains "http://") and (FolderPath endswith "\\winget.exe" or ProcessVersionInfoOriginalFileName =~ "winget.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "service_reconnaissance_via_wmic_exe" {
  name                       = "service_reconnaissance_via_wmic_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Service Reconnaissance Via Wmic.EXE"
  description                = "An adversary might use WMI to check if a certain remote service is running on a remote device. When the test completes, a service information will be displayed on the screen if it exists. A common feedback message is that \"No instance(s) Available\" if the service queried is not running. A common error message is \"Node - (provided IP or default) ERROR Description =The RPC server is unavailable\" if the provided remote host is unreachable"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "service" and (FolderPath endswith "\\WMIC.exe" or ProcessVersionInfoOriginalFileName =~ "wmic.exe")
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
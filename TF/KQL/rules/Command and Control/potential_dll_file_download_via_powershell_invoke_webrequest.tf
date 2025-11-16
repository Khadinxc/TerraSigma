resource "azurerm_sentinel_alert_rule_scheduled" "potential_dll_file_download_via_powershell_invoke_webrequest" {
  name                       = "potential_dll_file_download_via_powershell_invoke_webrequest"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential DLL File Download Via PowerShell Invoke-WebRequest"
  description                = "Detects potential DLL files being downloaded using the PowerShell Invoke-WebRequest or Invoke-RestMethod cmdlets."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Invoke-RestMethod " or ProcessCommandLine contains "Invoke-WebRequest " or ProcessCommandLine contains "IRM " or ProcessCommandLine contains "IWR ") and (ProcessCommandLine contains "http" and ProcessCommandLine contains "OutFile" and ProcessCommandLine contains ".dll")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl", "Execution"]
  techniques                 = ["T1059", "T1105"]
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
  }
}
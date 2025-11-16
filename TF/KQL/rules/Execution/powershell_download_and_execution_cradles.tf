resource "azurerm_sentinel_alert_rule_scheduled" "powershell_download_and_execution_cradles" {
  name                       = "powershell_download_and_execution_cradles"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Download and Execution Cradles"
  description                = "Detects PowerShell download and execution cradles. - Some PowerShell installers were seen using similar combinations. Apply filters accordingly"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".DownloadString(" or ProcessCommandLine contains ".DownloadFile(" or ProcessCommandLine contains "Invoke-WebRequest " or ProcessCommandLine contains "iwr " or ProcessCommandLine contains "Invoke-RestMethod " or ProcessCommandLine contains "irm ") and (ProcessCommandLine contains ";iex $" or ProcessCommandLine contains "| IEX" or ProcessCommandLine contains "|IEX " or ProcessCommandLine contains "I`E`X" or ProcessCommandLine contains "I`EX" or ProcessCommandLine contains "IE`X" or ProcessCommandLine contains "iex " or ProcessCommandLine contains "IEX (" or ProcessCommandLine contains "IEX(" or ProcessCommandLine contains "Invoke-Expression")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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
  }
}
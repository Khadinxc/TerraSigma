resource "azurerm_sentinel_alert_rule_scheduled" "powershell_defender_exclusion" {
  name                       = "powershell_defender_exclusion"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Powershell Defender Exclusion"
  description                = "Detects requests to exclude files, folders or processes from Antivirus scanning using PowerShell cmdlets - Possible Admin Activity - Other Cmdlets that may use the same parameters"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Add-MpPreference " or ProcessCommandLine contains "Set-MpPreference ") and (ProcessCommandLine contains " -ExclusionPath " or ProcessCommandLine contains " -ExclusionExtension " or ProcessCommandLine contains " -ExclusionProcess " or ProcessCommandLine contains " -ExclusionIpAddress ")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
  }
}
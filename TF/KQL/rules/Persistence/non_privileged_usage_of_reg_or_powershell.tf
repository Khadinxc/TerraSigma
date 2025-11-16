resource "azurerm_sentinel_alert_rule_scheduled" "non_privileged_usage_of_reg_or_powershell" {
  name                       = "non_privileged_usage_of_reg_or_powershell"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Non-privileged Usage of Reg or Powershell"
  description                = "Search for usage of reg or Powershell by non-privileged users to modify service configuration in registry"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "reg " and ProcessCommandLine contains "add") or (ProcessCommandLine contains "powershell" or ProcessCommandLine contains "set-itemproperty" or ProcessCommandLine contains " sp " or ProcessCommandLine contains "new-itemproperty")) and ((ProcessCommandLine contains "ImagePath" or ProcessCommandLine contains "FailureCommand" or ProcessCommandLine contains "ServiceDLL") and (ProcessCommandLine contains "ControlSet" and ProcessCommandLine contains "Services") and (ProcessIntegrityLevel in~ ("Medium", "S-1-16-8192")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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
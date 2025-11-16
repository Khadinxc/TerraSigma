resource "azurerm_sentinel_alert_rule_scheduled" "dropping_of_password_filter_dll" {
  name                       = "dropping_of_password_filter_dll"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Dropping Of Password Filter DLL"
  description                = "Detects dropping of dll files in system32 that may be used to retrieve user credentials from LSASS"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" and ProcessCommandLine contains "scecli\\0" and ProcessCommandLine contains "reg add"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "CredentialAccess"]
  techniques                 = ["T1556"]
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
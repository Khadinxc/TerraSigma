resource "azurerm_sentinel_alert_rule_scheduled" "user_added_to_admin_group_via_dseditgroup" {
  name                       = "user_added_to_admin_group_via_dseditgroup"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "User Added To Admin Group Via DseditGroup"
  description                = "Detects attempts to create and/or add an account to the admin group, thus granting admin privileges. - Legitimate administration activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -o edit " and ProcessCommandLine contains " -a " and ProcessCommandLine contains " -t user" and ProcessCommandLine contains "admin") and FolderPath endswith "/dseditgroup"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "InitialAccess", "PrivilegeEscalation"]
  techniques                 = ["T1078"]
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
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
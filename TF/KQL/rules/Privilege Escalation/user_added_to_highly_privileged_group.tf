resource "azurerm_sentinel_alert_rule_scheduled" "user_added_to_highly_privileged_group" {
  name                       = "user_added_to_highly_privileged_group"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "User Added To Highly Privileged Group"
  description                = "Detects addition of users to highly privileged groups via \"Net\" or \"Add-LocalGroupMember\". - Administrative activity that must be investigated"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Group Policy Creator Owners" or ProcessCommandLine contains "Schema Admins") and ((ProcessCommandLine contains "localgroup " and ProcessCommandLine contains " /add") or (ProcessCommandLine contains "Add-LocalGroupMember " and ProcessCommandLine contains " -Group "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1098"]
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
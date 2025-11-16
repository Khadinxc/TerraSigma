resource "azurerm_sentinel_alert_rule_scheduled" "cve_2021_44077_poc_default_dropped_file" {
  name                       = "cve_2021_44077_poc_default_dropped_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "CVE-2021-44077 POC Default Dropped File"
  description                = "Detects the creation of \"msiexec.exe\" in the \"bin\" directory of the ManageEngine SupportCenter Plus (Related to CVE-2021-44077) and public POC available (See references section) - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\ManageEngine\\SupportCenterPlus\\bin\\msiexec.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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
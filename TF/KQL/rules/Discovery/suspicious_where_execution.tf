resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_where_execution" {
  name                       = "suspicious_where_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Where Execution"
  description                = "Adversaries may enumerate browser bookmarks to learn more about compromised hosts. Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure."
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\where.exe" or ProcessVersionInfoOriginalFileName =~ "where.exe") and (ProcessCommandLine contains "places.sqlite" or ProcessCommandLine contains "cookies.sqlite" or ProcessCommandLine contains "formhistory.sqlite" or ProcessCommandLine contains "logins.json" or ProcessCommandLine contains "key4.db" or ProcessCommandLine contains "key3.db" or ProcessCommandLine contains "sessionstore.jsonlz4" or ProcessCommandLine contains "History" or ProcessCommandLine contains "Bookmarks" or ProcessCommandLine contains "Cookies" or ProcessCommandLine contains "Login Data")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1217"]
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
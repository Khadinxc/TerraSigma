resource "azurerm_sentinel_alert_rule_scheduled" "curl_web_request_with_potential_custom_user_agent" {
  name                       = "curl_web_request_with_potential_custom_user_agent"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Curl Web Request With Potential Custom User-Agent"
  description                = "Detects execution of \"curl.exe\" with a potential custom \"User-Agent\". Attackers can leverage this to download or exfiltrate data via \"curl\" to a domain that only accept specific \"User-Agent\" strings"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "User-Agent:" and ProcessCommandLine matches regex "\\s-H\\s") and (FolderPath endswith "\\curl.exe" or ProcessVersionInfoOriginalFileName =~ "curl.exe")
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
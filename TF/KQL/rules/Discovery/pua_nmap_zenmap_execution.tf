resource "azurerm_sentinel_alert_rule_scheduled" "pua_nmap_zenmap_execution" {
  name                       = "pua_nmap_zenmap_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Nmap/Zenmap Execution"
  description                = "Detects usage of namp/zenmap. Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation - Legitimate administrator activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\nmap.exe" or FolderPath endswith "\\zennmap.exe") or (ProcessVersionInfoOriginalFileName in~ ("nmap.exe", "zennmap.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1046"]
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
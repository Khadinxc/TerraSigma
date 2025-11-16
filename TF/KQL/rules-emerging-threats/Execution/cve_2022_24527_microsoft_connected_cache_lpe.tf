resource "azurerm_sentinel_alert_rule_scheduled" "cve_2022_24527_microsoft_connected_cache_lpe" {
  name                       = "cve_2022_24527_microsoft_connected_cache_lpe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "CVE-2022-24527 Microsoft Connected Cache LPE"
  description                = "Detects files created during the local privilege exploitation of CVE-2022-24527 Microsoft Connected Cache"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "WindowsPowerShell\\Modules\\webAdministration\\webAdministration.psm1" and (not((RequestAccountName contains "AUTHORI" or RequestAccountName contains "AUTORI")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "PrivilegeEscalation"]
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
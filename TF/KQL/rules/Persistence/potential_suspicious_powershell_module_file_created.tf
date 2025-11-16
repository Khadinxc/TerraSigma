resource "azurerm_sentinel_alert_rule_scheduled" "potential_suspicious_powershell_module_file_created" {
  name                       = "potential_suspicious_powershell_module_file_created"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Suspicious PowerShell Module File Created"
  description                = "Detects the creation of a new PowerShell module in the first folder of the module directory structure \"\\WindowsPowerShell\\Modules\\malware\\malware.psm1\". This is somewhat an uncommon practice as legitimate modules often includes a version folder."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "\\WindowsPowerShell\\Modules\\" and FolderPath contains "\\.ps") or (FolderPath contains "\\WindowsPowerShell\\Modules\\" and FolderPath contains "\\.dll")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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
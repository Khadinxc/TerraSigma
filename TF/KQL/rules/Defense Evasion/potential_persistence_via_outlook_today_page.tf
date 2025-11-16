resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_outlook_today_page" {
  name                       = "potential_persistence_via_outlook_today_page"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Outlook Today Page"
  description                = "Detects potential persistence activity via outlook today page. An attacker can set a custom page to execute arbitrary code and link to it via the registry values \"URL\" and \"UserDefinedUrl\"."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "Software\\Microsoft\\Office*" and RegistryKey endswith "\\Outlook\\Today*") and ((RegistryValueData =~ "DWORD (0x00000001)" and RegistryKey endswith "\\Stamp") or (RegistryKey endswith "\\URL" or RegistryKey endswith "\\UserDefinedUrl")) and (not((InitiatingProcessFolderPath endswith "\\OfficeClickToRun.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\Updates\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence"]
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
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}
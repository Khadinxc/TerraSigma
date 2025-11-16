resource "azurerm_sentinel_alert_rule_scheduled" "uefi_persistence_via_wpbbin_processcreation" {
  name                       = "uefi_persistence_via_wpbbin_processcreation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UEFI Persistence Via Wpbbin - ProcessCreation"
  description                = "Detects execution of the binary \"wpbbin\" which is used as part of the UEFI based persistence method described in the reference section - Legitimate usage of the file by hardware manufacturer such as lenovo (Thanks @0gtweet for the tip)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath =~ "C:\\Windows\\System32\\wpbbin.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1542"]
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
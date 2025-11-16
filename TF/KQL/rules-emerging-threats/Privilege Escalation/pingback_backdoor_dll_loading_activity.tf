resource "azurerm_sentinel_alert_rule_scheduled" "pingback_backdoor_dll_loading_activity" {
  name                       = "pingback_backdoor_dll_loading_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Pingback Backdoor DLL Loading Activity"
  description                = "Detects the use of Pingback backdoor that creates ICMP tunnel for C2 as described in the trustwave report - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath =~ "C:\\Windows\\oci.dll" and InitiatingProcessFolderPath endswith "\\msdtc.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion", "Persistence"]
  techniques                 = ["T1574"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "imagingdevices_unusual_parent_child_processes" {
  name                       = "imagingdevices_unusual_parent_child_processes"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ImagingDevices Unusual Parent/Child Processes"
  description                = "Detects unusual parent or children of the ImagingDevices.exe (Windows Contacts) process as seen being used with Bumblebee activity"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\ImagingDevices.exe" or (FolderPath endswith "\\ImagingDevices.exe" and (InitiatingProcessFolderPath endswith "\\WmiPrvSE.exe" or InitiatingProcessFolderPath endswith "\\svchost.exe" or InitiatingProcessFolderPath endswith "\\dllhost.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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
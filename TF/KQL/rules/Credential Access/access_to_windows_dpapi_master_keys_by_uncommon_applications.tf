resource "azurerm_sentinel_alert_rule_scheduled" "access_to_windows_dpapi_master_keys_by_uncommon_applications" {
  name                       = "access_to_windows_dpapi_master_keys_by_uncommon_applications"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Access To Windows DPAPI Master Keys By Uncommon Applications"
  description                = "Detects file access requests to the the Windows Data Protection API Master keys by an uncommon application. This can be a sign of credential stealing. Example case would be usage of mimikatz \"dpapi::masterkey\" function"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FileName contains "\\Microsoft\\Protect\\S-1-5-18\\" or FileName contains "\\Microsoft\\Protect\\S-1-5-21-") and (not((InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\system32\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysWOW64\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1555"]
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
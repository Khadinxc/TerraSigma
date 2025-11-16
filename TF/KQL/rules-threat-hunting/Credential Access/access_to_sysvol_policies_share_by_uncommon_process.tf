resource "azurerm_sentinel_alert_rule_scheduled" "access_to_sysvol_policies_share_by_uncommon_process" {
  name                       = "access_to_sysvol_policies_share_by_uncommon_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Access To Sysvol Policies Share By Uncommon Process"
  description                = "Detects file access requests to the Windows Sysvol Policies Share by uncommon processes"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where ((FileName contains "\\sysvol\\" and FileName contains "\\Policies\\") and FileName startswith "\\") and (not((InitiatingProcessFolderPath contains ":\\Program Files (x86)\\" or InitiatingProcessFolderPath contains ":\\Program Files\\" or InitiatingProcessFolderPath contains ":\\Windows\\explorer.exe" or InitiatingProcessFolderPath contains ":\\Windows\\system32\\" or InitiatingProcessFolderPath contains ":\\Windows\\SysWOW64\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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
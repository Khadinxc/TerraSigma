resource "azurerm_sentinel_alert_rule_scheduled" "image_load_susp_dll_load_system_process" {
  name                       = "image_load_susp_dll_load_system_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DLL Load By System Process From Suspicious Locations"
  description                = "Detects when a system process (i.e. located in system32, syswow64, etc.) loads a DLL from a suspicious location or a location with permissive permissions such as \"C:\\Users\\Public\" Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_susp_dll_load_system_process.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_susp_dll_load_system_process.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath startswith "C:\\Users\\Public\\" or FolderPath startswith "C:\\PerfLogs\\") and InitiatingProcessFolderPath startswith "C:\\Windows\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
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
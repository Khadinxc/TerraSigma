resource "azurerm_sentinel_alert_rule_scheduled" "system_control_panel_item_loaded_from_uncommon_location" {
  name                       = "system_control_panel_item_loaded_from_uncommon_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Control Panel Item Loaded From Uncommon Location"
  description                = "Detects image load events of system control panel items (.cpl) from uncommon or non-system locations which might be the result of sideloading."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\hdwwiz.cpl" or FolderPath endswith "\\appwiz.cpl") and (not((FolderPath contains ":\\Windows\\System32\\" or FolderPath contains ":\\Windows\\SysWOW64\\" or FolderPath contains ":\\Windows\\WinSxS\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
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
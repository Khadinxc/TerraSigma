resource "azurerm_sentinel_alert_rule_scheduled" "image_load_side_load_cpl_from_non_system_location" {
  name                       = "image_load_side_load_cpl_from_non_system_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Control Panel Item Loaded From Uncommon Location"
  description                = <<DESC
    Detects image load events of system control panel items (.cpl) from uncommon or non-system locations that may indicate DLL sideloading or other abuse techniques.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_side_load_cpl_from_non_system_location.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\appwiz.cpl" or FolderPath endswith "\\bthprops.cpl" or FolderPath endswith "\\hdwwiz.cpl") and (not((FolderPath startswith "C:\\Windows\\Prefetch\\" or FolderPath startswith "C:\\Windows\\System32\\" or FolderPath startswith "C:\\Windows\\SysWOW64\\" or FolderPath startswith "C:\\Windows\\WinSxS\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "PrivilegeEscalation"]
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
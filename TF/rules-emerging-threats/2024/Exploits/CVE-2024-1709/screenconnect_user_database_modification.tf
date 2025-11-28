resource "azurerm_sentinel_alert_rule_scheduled" "screenconnect_user_database_modification" {
  name                       = "screenconnect_user_database_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ScreenConnect User Database Modification"
  description                = "Detects file modifications to the temporary xml user database file indicating local user modification in the ScreenConnect server. This will occur during exploitation of the ScreenConnect Authentication Bypass vulnerability (CVE-2024-1709) in versions <23.9.8, but may also be observed when making legitimate modifications to local users or permissions. - This will occur legitimately as well and will result in some benign activity."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\ScreenConnect.Service.exe" and (FolderPath contains "Temp" and FolderPath contains "ScreenConnect") and FolderPath endswith ".xml"
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
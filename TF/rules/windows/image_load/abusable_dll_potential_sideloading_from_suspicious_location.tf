resource "azurerm_sentinel_alert_rule_scheduled" "abusable_dll_potential_sideloading_from_suspicious_location" {
  name                       = "abusable_dll_potential_sideloading_from_suspicious_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Abusable DLL Potential Sideloading From Suspicious Location"
  description                = "Detects potential DLL sideloading of DLLs that are known to be abused from suspicious locations"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\coreclr.dll" or FolderPath endswith "\\facesdk.dll" or FolderPath endswith "\\HPCustPartUI.dll" or FolderPath endswith "\\libcef.dll" or FolderPath endswith "\\ZIPDLL.dll") and ((FolderPath contains ":\\Perflogs\\" or FolderPath contains ":\\Users\\Public\\" or FolderPath contains "\\Temporary Internet" or FolderPath contains "\\Windows\\Temp\\") or ((FolderPath contains ":\\Users\\" and FolderPath contains "\\Favorites\\") or (FolderPath contains ":\\Users\\" and FolderPath contains "\\Favourites\\") or (FolderPath contains ":\\Users\\" and FolderPath contains "\\Contacts\\") or (FolderPath contains ":\\Users\\" and FolderPath contains "\\Pictures\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
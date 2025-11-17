resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_microsoft_office_startup_folder" {
  name                       = "potential_persistence_via_microsoft_office_startup_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Microsoft Office Startup Folder"
  description                = "Detects creation of Microsoft Office files inside of one of the default startup folders in order to achieve persistence. - Loading a user environment from a backup or a domain controller - Synchronization of templates"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (((FolderPath endswith ".doc" or FolderPath endswith ".docm" or FolderPath endswith ".docx" or FolderPath endswith ".dot" or FolderPath endswith ".dotm" or FolderPath endswith ".rtf") and (FolderPath contains "\\Microsoft\\Word\\STARTUP" or (FolderPath contains "\\Office" and FolderPath contains "\\Program Files" and FolderPath contains "\\STARTUP"))) or ((FolderPath endswith ".xls" or FolderPath endswith ".xlsm" or FolderPath endswith ".xlsx" or FolderPath endswith ".xlt" or FolderPath endswith ".xltm") and (FolderPath contains "\\Microsoft\\Excel\\XLSTART" or (FolderPath contains "\\Office" and FolderPath contains "\\Program Files" and FolderPath contains "\\XLSTART")))) and (not((InitiatingProcessFolderPath endswith "\\WINWORD.exe" or InitiatingProcessFolderPath endswith "\\EXCEL.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1137"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_file_created_in_office_startup_folder" {
  name                       = "uncommon_file_created_in_office_startup_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon File Created In Office Startup Folder"
  description                = "Detects the creation of a file with an uncommon extension in an Office application startup folder"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (((FolderPath contains "\\Microsoft\\Word\\STARTUP" or (FolderPath contains "\\Office" and FolderPath contains "\\Program Files" and FolderPath contains "\\STARTUP")) and (not((FolderPath endswith ".docb" or FolderPath endswith ".docm" or FolderPath endswith ".docx" or FolderPath endswith ".dotm" or FolderPath endswith ".mdb" or FolderPath endswith ".mdw" or FolderPath endswith ".pdf" or FolderPath endswith ".wll" or FolderPath endswith ".wwl")))) or ((FolderPath contains "\\Microsoft\\Excel\\XLSTART" or (FolderPath contains "\\Office" and FolderPath contains "\\Program Files" and FolderPath contains "\\XLSTART")) and (not((FolderPath endswith ".xll" or FolderPath endswith ".xls" or FolderPath endswith ".xlsm" or FolderPath endswith ".xlsx" or FolderPath endswith ".xlt" or FolderPath endswith ".xltm" or FolderPath endswith ".xlw"))))) and (not((((InitiatingProcessFolderPath contains ":\\Program Files\\Microsoft Office\\" or InitiatingProcessFolderPath contains ":\\Program Files (x86)\\Microsoft Office\\") and (InitiatingProcessFolderPath endswith "\\winword.exe" or InitiatingProcessFolderPath endswith "\\excel.exe")) or (InitiatingProcessFolderPath contains ":\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\" and InitiatingProcessFolderPath endswith "\\OfficeClickToRun.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1587"]
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
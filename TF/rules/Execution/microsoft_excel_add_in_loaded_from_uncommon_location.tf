resource "azurerm_sentinel_alert_rule_scheduled" "microsoft_excel_add_in_loaded_from_uncommon_location" {
  name                       = "microsoft_excel_add_in_loaded_from_uncommon_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Microsoft Excel Add-In Loaded From Uncommon Location"
  description                = "Detects Microsoft Excel loading an Add-In (.xll) file from an uncommon location - Some tuning might be required to allow or remove certain locations used by the rule if you consider them as safe locations"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath contains "\\Desktop\\" or FolderPath contains "\\Downloads\\" or FolderPath contains "\\Perflogs\\" or FolderPath contains "\\Temp\\" or FolderPath contains "\\Users\\Public\\" or FolderPath contains "\\Windows\\Tasks\\") and FolderPath endswith ".xll" and InitiatingProcessFolderPath endswith "\\excel.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1204"]
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
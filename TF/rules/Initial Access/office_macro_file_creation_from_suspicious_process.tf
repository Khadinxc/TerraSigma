resource "azurerm_sentinel_alert_rule_scheduled" "office_macro_file_creation_from_suspicious_process" {
  name                       = "office_macro_file_creation_from_suspicious_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Office Macro File Creation From Suspicious Process"
  description                = "Detects the creation of a office macro file from a a suspicious process"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where ((InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\regsvr32.exe" or InitiatingProcessFolderPath endswith "\\rundll32.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe") or (InitiatingProcessParentFileName in~ ("cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "wscript.exe"))) and (FolderPath endswith ".docm" or FolderPath endswith ".dotm" or FolderPath endswith ".xlsm" or FolderPath endswith ".xltm" or FolderPath endswith ".potm" or FolderPath endswith ".pptm")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1566"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
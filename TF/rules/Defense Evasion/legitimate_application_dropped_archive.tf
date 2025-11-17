resource "azurerm_sentinel_alert_rule_scheduled" "legitimate_application_dropped_archive" {
  name                       = "legitimate_application_dropped_archive"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Legitimate Application Dropped Archive"
  description                = "Detects programs on a Windows system that should not write an archive to disk"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\winword.exe" or InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\msaccess.exe" or InitiatingProcessFolderPath endswith "\\mspub.exe" or InitiatingProcessFolderPath endswith "\\eqnedt32.exe" or InitiatingProcessFolderPath endswith "\\visio.exe" or InitiatingProcessFolderPath endswith "\\wordpad.exe" or InitiatingProcessFolderPath endswith "\\wordview.exe" or InitiatingProcessFolderPath endswith "\\certutil.exe" or InitiatingProcessFolderPath endswith "\\certoc.exe" or InitiatingProcessFolderPath endswith "\\CertReq.exe" or InitiatingProcessFolderPath endswith "\\Desktopimgdownldr.exe" or InitiatingProcessFolderPath endswith "\\esentutl.exe" or InitiatingProcessFolderPath endswith "\\finger.exe" or InitiatingProcessFolderPath endswith "\\notepad.exe" or InitiatingProcessFolderPath endswith "\\AcroRd32.exe" or InitiatingProcessFolderPath endswith "\\RdrCEF.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\hh.exe") and (FolderPath endswith ".zip" or FolderPath endswith ".rar" or FolderPath endswith ".7z" or FolderPath endswith ".diagcab" or FolderPath endswith ".appx")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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
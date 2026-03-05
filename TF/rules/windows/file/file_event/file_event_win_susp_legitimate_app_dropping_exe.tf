resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_susp_legitimate_app_dropping_exe" {
  name                       = "file_event_win_susp_legitimate_app_dropping_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Legitimate Application Dropped Executable"
  description                = <<DESC
    Detects programs on a Windows system that should not write executables to disk

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_exe.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\eqnedt32.exe" or InitiatingProcessFolderPath endswith "\\wordpad.exe" or InitiatingProcessFolderPath endswith "\\wordview.exe" or InitiatingProcessFolderPath endswith "\\certutil.exe" or InitiatingProcessFolderPath endswith "\\certoc.exe" or InitiatingProcessFolderPath endswith "\\CertReq.exe" or InitiatingProcessFolderPath endswith "\\Desktopimgdownldr.exe" or InitiatingProcessFolderPath endswith "\\esentutl.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\AcroRd32.exe" or InitiatingProcessFolderPath endswith "\\RdrCEF.exe" or InitiatingProcessFolderPath endswith "\\hh.exe" or InitiatingProcessFolderPath endswith "\\finger.exe") and (FolderPath endswith ".exe" or FolderPath endswith ".dll" or FolderPath endswith ".ocx")
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
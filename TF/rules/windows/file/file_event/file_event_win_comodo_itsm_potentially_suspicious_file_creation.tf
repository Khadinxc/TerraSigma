resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_comodo_itsm_potentially_suspicious_file_creation" {
  name                       = "file_event_win_comodo_itsm_potentially_suspicious_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious File Creation by OpenEDR's ITSMService"
  description                = "Detects the creation of potentially suspicious files by OpenEDR's ITSMService process. The ITSMService is responsible for remote management operations and can create files on the system through the Process Explorer or file management features. While legitimate for IT operations, creation of executable or script files could indicate unauthorized file uploads, data staging, or malicious file deployment. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_comodo_itsm_potentially_suspicious_file_creation.yml - Legitimate OpenEDR file management operations - Authorized remote file uploads by IT administrators - Software deployment through OpenEDR console | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_comodo_itsm_potentially_suspicious_file_creation.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\COMODO\\Endpoint Manager\\ITSMService.exe" and (FolderPath endswith ".7z" or FolderPath endswith ".bat" or FolderPath endswith ".cmd" or FolderPath endswith ".com" or FolderPath endswith ".dll" or FolderPath endswith ".exe" or FolderPath endswith ".hta" or FolderPath endswith ".js" or FolderPath endswith ".pif" or FolderPath endswith ".ps1" or FolderPath endswith ".rar" or FolderPath endswith ".scr" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs" or FolderPath endswith ".zip")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl", "LateralMovement"]
  techniques                 = ["T1105", "T1570", "T1219"]
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
resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_create_non_existent_dlls" {
  name                       = "file_event_win_create_non_existent_dlls"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Creation Of Non-Existent System DLL"
  description                = <<DESC
    Detects creation of specific system DLL files that are  usually not present on the system (or at least not in system directories) but may be loaded by legitimate processes. Phantom DLL hijacking involves placing malicious DLLs with names of non-existent system binaries in locations where legitimate applications may search for them, leading to execution of the malicious DLLs. Thus, the creation of such DLLs may indicate preparation for phantom DLL hijacking attacks.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_create_non_existent_dlls.yml
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ":\\Windows\\System32\\axeonoffhelper.dll" or FolderPath endswith ":\\Windows\\System32\\cdpsgshims.dll" or FolderPath endswith ":\\Windows\\System32\\oci.dll" or FolderPath endswith ":\\Windows\\System32\\offdmpsvc.dll" or FolderPath endswith ":\\Windows\\System32\\shellchromeapi.dll" or FolderPath endswith ":\\Windows\\System32\\TSMSISrv.dll" or FolderPath endswith ":\\Windows\\System32\\TSVIPSrv.dll" or FolderPath endswith ":\\Windows\\System32\\wbem\\wbemcomn.dll" or FolderPath endswith ":\\Windows\\System32\\WLBSCTRL.dll" or FolderPath endswith ":\\Windows\\System32\\wow64log.dll" or FolderPath endswith ":\\Windows\\System32\\WptsExtensions.dll" or FolderPath endswith "\\SprintCSP.dll"
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
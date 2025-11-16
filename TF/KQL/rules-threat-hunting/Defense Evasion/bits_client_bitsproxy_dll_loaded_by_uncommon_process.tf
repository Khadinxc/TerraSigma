resource "azurerm_sentinel_alert_rule_scheduled" "bits_client_bitsproxy_dll_loaded_by_uncommon_process" {
  name                       = "bits_client_bitsproxy_dll_loaded_by_uncommon_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "BITS Client BitsProxy DLL Loaded By Uncommon Process"
  description                = "Detects an uncommon process loading the \"BitsProxy.dll\". This DLL is used when the BITS COM instance or API is used. This detection can be used to hunt for uncommon processes loading this DLL in your environment. Which may indicate potential suspicious activity occurring. - Allowed binaries in the environment that do BITS Jobs"
  severity                   = "Low"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\BitsProxy.dll" and (not((InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\aitstatic.exe", "C:\\Windows\\System32\\bitsadmin.exe", "C:\\Windows\\System32\\desktopimgdownldr.exe", "C:\\Windows\\System32\\DeviceEnroller.exe", "C:\\Windows\\System32\\MDMAppInstaller.exe", "C:\\Windows\\System32\\ofdeploy.exe", "C:\\Windows\\System32\\RecoveryDrive.exe", "C:\\Windows\\System32\\Speech_OneCore\\common\\SpeechModelDownload.exe", "C:\\Windows\\SysWOW64\\bitsadmin.exe", "C:\\Windows\\SysWOW64\\OneDriveSetup.exe", "C:\\Windows\\SysWOW64\\Speech_OneCore\\Common\\SpeechModelDownload.exe")))) and (not(InitiatingProcessFolderPath =~ "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence"]
  techniques                 = ["T1197"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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
resource "azurerm_sentinel_alert_rule_scheduled" "use_ntfs_short_name_in_image" {
  name                       = "use_ntfs_short_name_in_image"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Use NTFS Short Name in Image"
  description                = "Detect use of the Windows 8.3 short name. Which could be used as a method to avoid Image based detection - Software Installers"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath contains "~1.bat" or FolderPath contains "~1.dll" or FolderPath contains "~1.exe" or FolderPath contains "~1.hta" or FolderPath contains "~1.js" or FolderPath contains "~1.msi" or FolderPath contains "~1.ps1" or FolderPath contains "~1.tmp" or FolderPath contains "~1.vbe" or FolderPath contains "~1.vbs" or FolderPath contains "~2.bat" or FolderPath contains "~2.dll" or FolderPath contains "~2.exe" or FolderPath contains "~2.hta" or FolderPath contains "~2.js" or FolderPath contains "~2.msi" or FolderPath contains "~2.ps1" or FolderPath contains "~2.tmp" or FolderPath contains "~2.vbe" or FolderPath contains "~2.vbs") and (not(InitiatingProcessFolderPath =~ "C:\\Windows\\explorer.exe")) and (not((InitiatingProcessFolderPath endswith "\\thor\\thor64.exe" or FolderPath endswith "\\VCREDI~1.EXE" or InitiatingProcessFolderPath endswith "\\WebEx\\WebexHost.exe" or FolderPath =~ "C:\\PROGRA~1\\WinZip\\WZPREL~1.EXE")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1564"]
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
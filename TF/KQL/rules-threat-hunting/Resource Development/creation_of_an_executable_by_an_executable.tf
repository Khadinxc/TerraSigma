resource "azurerm_sentinel_alert_rule_scheduled" "creation_of_an_executable_by_an_executable" {
  name                       = "creation_of_an_executable_by_an_executable"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Creation of an Executable by an Executable"
  description                = "Detects the creation of an executable by another executable. - Software installers - Update utilities - 32bit applications launching their 64bit versions"
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith ".exe" and FolderPath endswith ".exe") and (not(((InitiatingProcessFolderPath contains ":\\ProgramData\\Microsoft\\Windows Defender\\" or InitiatingProcessFolderPath contains ":\\Program Files\\Windows Defender\\") or (InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\Framework" and InitiatingProcessFolderPath endswith "\\mscorsvw.exe" and FolderPath contains ":\\Windows\\assembly") or (InitiatingProcessFolderPath endswith ":\\Windows\\System32\\msiexec.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\system32\\cleanmgr.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\explorer.exe" or InitiatingProcessFolderPath endswith ":\\WINDOWS\\system32\\dxgiadaptercache.exe" or InitiatingProcessFolderPath endswith ":\\WINDOWS\\system32\\Dism.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\System32\\wuauclt.exe") or (InitiatingProcessFolderPath endswith "\\AppData\\Local\\GitHubDesktop\\Update.exe" and FolderPath contains "\\AppData\\Local\\SquirrelTemp\\") or ((InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\Framework\\" or InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\Framework64\\" or InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\FrameworkArm\\" or InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\FrameworkArm64\\") and InitiatingProcessFolderPath endswith "\\mscorsvw.exe" and FolderPath contains ":\\Windows\\assembly\\NativeImages_") or ((InitiatingProcessFolderPath contains ":\\Program Files\\" or InitiatingProcessFolderPath contains ":\\Program Files (x86)\\") or (FolderPath contains ":\\Program Files\\" or FolderPath contains ":\\Program Files (x86)\\")) or (InitiatingProcessFolderPath endswith "\\AppData\\Local\\Microsoft\\Teams\\Update.exe" and (FolderPath endswith "\\AppData\\Local\\Microsoft\\Teams\\stage\\Teams.exe" or FolderPath endswith "\\AppData\\Local\\Microsoft\\Teams\\stage\\Squirrel.exe" or FolderPath endswith "\\AppData\\Local\\Microsoft\\SquirrelTemp\\tempb\\")) or (InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\" or FolderPath contains "\\AppData\\Local\\Temp\\") or (InitiatingProcessFolderPath contains ":\\Windows\\WinSxS\\" and InitiatingProcessFolderPath endswith "\\TiWorker.exe") or (InitiatingProcessFolderPath endswith ":\\WINDOWS\\system32\\svchost.exe" and FolderPath contains ":\\Windows\\SoftwareDistribution\\Download\\") or (InitiatingProcessFolderPath endswith ":\\Windows\\system32\\svchost.exe" and (FolderPath contains ":\\WUDownloadCache\\" and FolderPath contains "\\WindowsUpdateBox.exe")) or (InitiatingProcessFolderPath contains "\\AppData\\Local\\" and InitiatingProcessFolderPath endswith "\\Microsoft VS Code\\Code.exe" and FolderPath contains "\\.vscode\\extensions\\") or FolderPath contains "\\AppData\\Local\\Microsoft\\WindowsApps\\" or (InitiatingProcessFolderPath contains ":\\WINDOWS\\TEMP\\" or FolderPath contains ":\\WINDOWS\\TEMP\\") or (InitiatingProcessFolderPath contains ":\\WINDOWS\\SoftwareDistribution\\Download\\" and InitiatingProcessFolderPath endswith "\\WindowsUpdateBox.Exe" and FolderPath contains ":\\$WINDOWS.~BT\\Sources\\")))) and (not(((InitiatingProcessFolderPath endswith "\\ChromeSetup.exe" and FolderPath contains "\\Google") or (InitiatingProcessFolderPath contains "\\Python27\\python.exe" and (FolderPath contains "\\Python27\\Lib\\site-packages\\" or FolderPath contains "\\Python27\\Scripts\\" or FolderPath contains "\\AppData\\Local\\Temp\\")) or (InitiatingProcessFolderPath contains "\\AppData\\Local\\SquirrelTemp\\Update.exe" and FolderPath contains "\\AppData\\Local"))))
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
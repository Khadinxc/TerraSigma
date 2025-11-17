resource "azurerm_sentinel_alert_rule_scheduled" "powershell_core_dll_loaded_by_non_powershell_process" {
  name                       = "powershell_core_dll_loaded_by_non_powershell_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Core DLL Loaded By Non PowerShell Process"
  description                = "Detects loading of essential DLLs used by PowerShell by non-PowerShell process. Detects behavior similar to meterpreter's \"load powershell\" extension. - Used by some .NET binaries, minimal on user workstation. - Used by Microsoft SQL Server Management Studio"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (InitiatingProcessVersionInfoFileDescription =~ "System.Management.Automation" or InitiatingProcessVersionInfoOriginalFileName =~ "System.Management.Automation.dll" or (FolderPath endswith "\\System.Management.Automation.dll" or FolderPath endswith "\\System.Management.Automation.ni.dll")) and (not(((InitiatingProcessFolderPath endswith "\\mscorsvw.exe" and (InitiatingProcessFolderPath startswith "C:\\Windows\\Microsoft.NET\\Framework\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\Microsoft.NET\\FrameworkArm\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\Microsoft.NET\\FrameworkArm64\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\Microsoft.NET\\Framework64\\")) or (InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\dsac.exe", "C:\\WINDOWS\\System32\\RemoteFXvGPUDisablement.exe", "C:\\Windows\\System32\\runscripthelper.exe", "C:\\WINDOWS\\System32\\sdiagnhost.exe", "C:\\Windows\\System32\\ServerManager.exe", "C:\\Windows\\System32\\SyncAppvPublishingServer.exe", "C:\\Windows\\System32\\winrshost.exe", "C:\\Windows\\System32\\wsmprovhost.exe", "C:\\Windows\\SysWOW64\\winrshost.exe", "C:\\Windows\\SysWOW64\\wsmprovhost.exe")) or (InitiatingProcessFolderPath in~ ("C:\\Program Files\\PowerShell\\7-preview\\pwsh.exe", "C:\\Program Files\\PowerShell\\7\\pwsh.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell_ise.exe", "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe")) or ((InitiatingProcessFolderPath contains "C:\\Program Files\\WindowsApps\\Microsoft.PowerShellPreview" or InitiatingProcessFolderPath contains "\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.PowerShellPreview") and InitiatingProcessFolderPath endswith "\\pwsh.exe")))) and (not((isnull(InitiatingProcessFolderPath) or InitiatingProcessFolderPath startswith "C:\\ProgramData\\chocolatey\\choco.exe" or InitiatingProcessFolderPath endswith "\\Citrix\\ConfigSync\\ConfigSyncRun.exe" or ((InitiatingProcessFolderPath endswith "\\thor64.exe" or InitiatingProcessFolderPath endswith "\\thor.exe") and InitiatingProcessFolderPath startswith "C:\\Windows\\Temp\\asgard2-agent\\") or (InitiatingProcessFolderPath endswith "\\IDE\\Ssms.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft SQL Server Management Studio" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft SQL Server Management Studio")) or (InitiatingProcessFolderPath endswith "\\Tools\\Binn\\SQLPS.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft SQL Server\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft SQL Server\\")) or (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft Visual Studio\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft Visual Studio\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
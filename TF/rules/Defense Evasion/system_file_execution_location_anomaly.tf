resource "azurerm_sentinel_alert_rule_scheduled" "system_file_execution_location_anomaly" {
  name                       = "system_file_execution_location_anomaly"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System File Execution Location Anomaly"
  description                = "Detects the execution of a Windows system binary that is usually located in the system folder from an uncommon location."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\atbroker.exe" or FolderPath endswith "\\audiodg.exe" or FolderPath endswith "\\bcdedit.exe" or FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\certreq.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cmstp.exe" or FolderPath endswith "\\conhost.exe" or FolderPath endswith "\\consent.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\csrss.exe" or FolderPath endswith "\\dashost.exe" or FolderPath endswith "\\defrag.exe" or FolderPath endswith "\\dfrgui.exe" or FolderPath endswith "\\dism.exe" or FolderPath endswith "\\dllhost.exe" or FolderPath endswith "\\dllhst3g.exe" or FolderPath endswith "\\dwm.exe" or FolderPath endswith "\\eventvwr.exe" or FolderPath endswith "\\logonui.exe" or FolderPath endswith "\\LsaIso.exe" or FolderPath endswith "\\lsass.exe" or FolderPath endswith "\\lsm.exe" or FolderPath endswith "\\msiexec.exe" or FolderPath endswith "\\ntoskrnl.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\runonce.exe" or FolderPath endswith "\\RuntimeBroker.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\services.exe" or FolderPath endswith "\\sihost.exe" or FolderPath endswith "\\smartscreen.exe" or FolderPath endswith "\\smss.exe" or FolderPath endswith "\\spoolsv.exe" or FolderPath endswith "\\svchost.exe" or FolderPath endswith "\\taskhost.exe" or FolderPath endswith "\\taskhostw.exe" or FolderPath endswith "\\Taskmgr.exe" or FolderPath endswith "\\userinit.exe" or FolderPath endswith "\\wininit.exe" or FolderPath endswith "\\winlogon.exe" or FolderPath endswith "\\winver.exe" or FolderPath endswith "\\wlanext.exe" or FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\wsl.exe" or FolderPath endswith "\\wsmprovhost.exe") and (not(((FolderPath startswith "C:\\$WINDOWS.~BT\\" or FolderPath startswith "C:\\$WinREAgent\\" or FolderPath startswith "C:\\Windows\\SoftwareDistribution\\" or FolderPath startswith "C:\\Windows\\System32\\" or FolderPath startswith "C:\\Windows\\SystemTemp\\" or FolderPath startswith "C:\\Windows\\SysWOW64\\" or FolderPath startswith "C:\\Windows\\uus\\" or FolderPath startswith "C:\\Windows\\WinSxS\\") or ((FolderPath contains "C:\\Program Files\\PowerShell\\7\\" or FolderPath contains "C:\\Program Files\\PowerShell\\7-preview\\" or FolderPath contains "C:\\Program Files\\WindowsApps\\Microsoft.PowerShellPreview" or FolderPath contains "\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.PowerShellPreview") and FolderPath endswith "\\pwsh.exe") or (FolderPath contains "\\AppData\\Local\\Microsoft\\WindowsApps\\" and FolderPath endswith "\\wsl.exe" and FolderPath startswith "C:\\Users\\'") or (FolderPath endswith "\\wsl.exe" and (FolderPath startswith "C:\\Program Files\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux" or FolderPath startswith "C:\\Program Files\\WSL\\"))))) and (not(FolderPath contains "\\SystemRoot\\System32\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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
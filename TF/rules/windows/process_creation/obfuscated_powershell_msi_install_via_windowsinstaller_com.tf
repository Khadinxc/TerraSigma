resource "azurerm_sentinel_alert_rule_scheduled" "obfuscated_powershell_msi_install_via_windowsinstaller_com" {
  name                       = "obfuscated_powershell_msi_install_via_windowsinstaller_com"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Obfuscated PowerShell MSI Install via WindowsInstaller COM"
  description                = "Detects the execution of obfuscated PowerShell commands that attempt to install MSI packages via the Windows Installer COM object (`WindowsInstaller.Installer`). The technique involves manipulating strings to hide functionality, such as constructing class names using string insertion (e.g., 'indowsInstaller.Installer'.Insert(0,'W')) and correcting malformed URLs (e.g., converting 'htps://' to 'https://') at runtime. This behavior is commonly associated with malware loaders or droppers that aim to bypass static detection by hiding intent in runtime-generated strings and using legitimate tools for code execution. The use of `InstallProduct` and COM object creation, particularly combined with hidden window execution and suppressed UI, indicates an attempt to install software (likely malicious) without user interaction."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-ComObject" and ProcessCommandLine contains "InstallProduct(" and ProcessCommandLine contains ".Insert(" and ProcessCommandLine contains "UILevel") and ((FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell_ISE.EXE", "PowerShell.EXE", "pwsh.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1027", "T1218", "T1059"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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
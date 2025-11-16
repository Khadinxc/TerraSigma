resource "azurerm_sentinel_alert_rule_scheduled" "powershell_msi_install_via_windowsinstaller_com_from_remote_location" {
  name                       = "powershell_msi_install_via_windowsinstaller_com_from_remote_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell MSI Install via WindowsInstaller COM From Remote Location"
  description                = "Detects the execution of PowerShell commands that attempt to install MSI packages via the Windows Installer COM object (`WindowsInstaller.Installer`) hosted remotely. This could be indication of malicious software deployment or lateral movement attempts using Windows Installer functionality. And the usage of WindowsInstaller COM object rather than msiexec could be an attempt to bypass the detection."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "-ComObject" and ProcessCommandLine contains "InstallProduct(") and ((FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell_ISE.EXE", "PowerShell.EXE", "pwsh.dll"))) and (ProcessCommandLine contains "http" or ProcessCommandLine contains "\\\\")) and (not((ProcessCommandLine contains "://127.0.0.1" or ProcessCommandLine contains "://localhost")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion", "CommandAndControl"]
  techniques                 = ["T1059", "T1218", "T1105"]
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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
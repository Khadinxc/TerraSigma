resource "azurerm_sentinel_alert_rule_scheduled" "non_interactive_powershell_process_spawned" {
  name                       = "non_interactive_powershell_process_spawned"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Non Interactive PowerShell Process Spawned"
  description                = "Detects non-interactive PowerShell activity by looking at the \"powershell\" process with a non-user GUI process such as \"explorer.exe\" as a parent. - Likely. Many admin scripts and tools leverage PowerShell in their BAT or VB scripts which may trigger this rule often. It is best to add additional filters or use this to hunt for anomalies"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll"))) and (not(((InitiatingProcessFolderPath endswith ":\\Windows\\explorer.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\System32\\CompatTelRunner.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\SysWOW64\\explorer.exe") or InitiatingProcessFolderPath =~ ":\\$WINDOWS.~BT\\Sources\\SetupHost.exe"))) and (not(((InitiatingProcessFolderPath contains ":\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_" and InitiatingProcessFolderPath endswith "\\WindowsTerminal.exe") or (InitiatingProcessCommandLine contains " --ms-enable-electron-run-as-node " and InitiatingProcessFolderPath endswith "\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"))))
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
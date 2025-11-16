resource "azurerm_sentinel_alert_rule_scheduled" "always_install_elevated_msi_spawned_cmd_and_powershell" {
  name                       = "always_install_elevated_msi_spawned_cmd_and_powershell"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Always Install Elevated MSI Spawned Cmd And Powershell"
  description                = "Detects Windows Installer service (msiexec.exe) spawning \"cmd\" or \"powershell\""
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("Cmd.Exe", "PowerShell.EXE", "pwsh.dll"))) and ((InitiatingProcessFolderPath contains "\\Windows\\Installer\\" and InitiatingProcessFolderPath contains "msi") and InitiatingProcessFolderPath endswith "tmp")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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
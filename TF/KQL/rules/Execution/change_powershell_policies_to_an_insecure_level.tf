resource "azurerm_sentinel_alert_rule_scheduled" "change_powershell_policies_to_an_insecure_level" {
  name                       = "change_powershell_policies_to_an_insecure_level"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Change PowerShell Policies to an Insecure Level"
  description                = "Detects changing the PowerShell script execution policy to a potentially insecure level using the \"-ExecutionPolicy\" flag. - Administrator scripts"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessVersionInfoOriginalFileName in~ ("powershell_ise.exe", "PowerShell.EXE", "pwsh.dll")) or (FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe")) and (ProcessCommandLine contains "Bypass" or ProcessCommandLine contains "Unrestricted") and (ProcessCommandLine contains "-executionpolicy " or ProcessCommandLine contains " -ep " or ProcessCommandLine contains " -exec ")) and (not(((ProcessCommandLine contains "-NoProfile -ExecutionPolicy Bypass -File \"C:\\Program Files\\PowerShell\\7\\" or ProcessCommandLine contains "-NoProfile -ExecutionPolicy Bypass -File \"C:\\Program Files (x86)\\PowerShell\\7\\") and (InitiatingProcessFolderPath in~ ("C:\\Windows\\SysWOW64\\msiexec.exe", "C:\\Windows\\System32\\msiexec.exe"))))) and (not(((ProcessCommandLine contains "-ExecutionPolicy ByPass -File \"C:\\Program Files\\Avast Software\\Avast" or ProcessCommandLine contains "-ExecutionPolicy ByPass -File \"C:\\Program Files (x86)\\Avast Software\\Avast\\") and (InitiatingProcessFolderPath contains "C:\\Program Files\\Avast Software\\Avast\\" or InitiatingProcessFolderPath contains "C:\\Program Files (x86)\\Avast Software\\Avast\\" or InitiatingProcessFolderPath contains "\\instup.exe"))))
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
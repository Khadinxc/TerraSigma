resource "azurerm_sentinel_alert_rule_scheduled" "abused_debug_privilege_by_arbitrary_parent_processes" {
  name                       = "abused_debug_privilege_by_arbitrary_parent_processes"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Abused Debug Privilege by Arbitrary Parent Processes"
  description                = "Detection of unusual child processes by different system processes"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\cmd.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll", "Cmd.Exe"))) and ((InitiatingProcessFolderPath endswith "\\winlogon.exe" or InitiatingProcessFolderPath endswith "\\services.exe" or InitiatingProcessFolderPath endswith "\\lsass.exe" or InitiatingProcessFolderPath endswith "\\csrss.exe" or InitiatingProcessFolderPath endswith "\\smss.exe" or InitiatingProcessFolderPath endswith "\\wininit.exe" or InitiatingProcessFolderPath endswith "\\spoolsv.exe" or InitiatingProcessFolderPath endswith "\\searchindexer.exe") and (AccountName contains "AUTHORI" or AccountName contains "AUTORI"))) and (not((ProcessCommandLine contains " route " and ProcessCommandLine contains " ADD ")))
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
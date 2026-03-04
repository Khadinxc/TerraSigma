resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_keyscrambler_susp_child_process" {
  name                       = "proc_creation_win_keyscrambler_susp_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Child Process of KeyScrambler.exe"
  description                = "Detects potentially suspicious child processes of KeyScrambler.exe Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_keyscrambler_susp_child_process.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_keyscrambler_susp_child_process.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\wscript.exe") or (ProcessVersionInfoOriginalFileName in~ ("Cmd.Exe", "cscript.exe", "mshta.exe", "PowerShell.EXE", "pwsh.dll", "regsvr32.exe", "RUNDLL32.EXE", "wscript.exe"))) and InitiatingProcessFolderPath endswith "\\KeyScrambler.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "Execution", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1203", "T1574"]
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
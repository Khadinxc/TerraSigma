resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_wermgr_susp_child_process" {
  name                       = "proc_creation_win_wermgr_susp_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Child Process Of Wermgr.EXE"
  description                = "Detects suspicious Windows Error Reporting manager (wermgr.exe) child process Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wermgr_susp_child_process.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wermgr_susp_child_process.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\ipconfig.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe" or FolderPath endswith "\\netstat.exe" or FolderPath endswith "\\nslookup.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\systeminfo.exe" or FolderPath endswith "\\whoami.exe" or FolderPath endswith "\\wscript.exe") and InitiatingProcessFolderPath endswith "\\wermgr.exe") and (not(((ProcessCommandLine contains "-queuereporting" or ProcessCommandLine contains "-responsepester") and (ProcessCommandLine contains "C:\\Windows\\system32\\WerConCpl.dll" and ProcessCommandLine contains "LaunchErcApp ") and FolderPath endswith "\\rundll32.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1055", "T1036"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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
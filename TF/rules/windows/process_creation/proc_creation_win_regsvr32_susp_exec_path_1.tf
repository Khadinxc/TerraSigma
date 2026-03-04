resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_regsvr32_susp_exec_path_1" {
  name                       = "proc_creation_win_regsvr32_susp_exec_path_1"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Regsvr32 Execution From Potential Suspicious Location"
  description                = "Detects execution of regsvr32 where the DLL is located in a potentially suspicious location. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_regsvr32_susp_exec_path_1.yml - Some installers might execute \"regsvr32\" with DLLs located in %TEMP% or in %PROGRAMDATA%. Apply additional filters if necessary. | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_regsvr32_susp_exec_path_1.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ":\\ProgramData\\" or ProcessCommandLine contains ":\\Temp\\" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\" or ProcessCommandLine contains "\\AppData\\Roaming\\") and (FolderPath endswith "\\regsvr32.exe" or ProcessVersionInfoOriginalFileName =~ "REGSVR32.EXE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
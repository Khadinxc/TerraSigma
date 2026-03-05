resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_wmic_susp_process_creation" {
  name                       = "proc_creation_win_wmic_susp_process_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Process Created Via Wmic.EXE"
  description                = <<DESC
    Detects WMIC executing "process call create" with suspicious calls to processes such as "rundll32", "regsrv32", etc.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wmic_susp_process_creation.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "rundll32" or ProcessCommandLine contains "bitsadmin" or ProcessCommandLine contains "regsvr32" or ProcessCommandLine contains "cmd.exe /c " or ProcessCommandLine contains "cmd.exe /k " or ProcessCommandLine contains "cmd.exe /r " or ProcessCommandLine contains "cmd /c " or ProcessCommandLine contains "cmd /k " or ProcessCommandLine contains "cmd /r " or ProcessCommandLine contains "powershell" or ProcessCommandLine contains "pwsh" or ProcessCommandLine contains "certutil" or ProcessCommandLine contains "cscript" or ProcessCommandLine contains "wscript" or ProcessCommandLine contains "mshta" or ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "\\Windows\\Temp\\" or ProcessCommandLine contains "\\AppData\\Local\\" or ProcessCommandLine contains "%temp%" or ProcessCommandLine contains "%tmp%" or ProcessCommandLine contains "%ProgramData%" or ProcessCommandLine contains "%appdata%" or ProcessCommandLine contains "%comspec%" or ProcessCommandLine contains "%localappdata%") and (ProcessCommandLine contains "process " and ProcessCommandLine contains "call " and ProcessCommandLine contains "create ")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1047"]
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
}
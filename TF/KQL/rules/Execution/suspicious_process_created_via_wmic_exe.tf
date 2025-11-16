resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_process_created_via_wmic_exe" {
  name                       = "suspicious_process_created_via_wmic_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Process Created Via Wmic.EXE"
  description                = "Detects WMIC executing \"process call create\" with suspicious calls to processes such as \"rundll32\", \"regsrv32\", etc."
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}
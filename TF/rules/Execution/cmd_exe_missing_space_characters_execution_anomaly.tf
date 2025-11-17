resource "azurerm_sentinel_alert_rule_scheduled" "cmd_exe_missing_space_characters_execution_anomaly" {
  name                       = "cmd_exe_missing_space_characters_execution_anomaly"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Cmd.EXE Missing Space Characters Execution Anomaly"
  description                = "Detects Windows command lines that miss a space before or after the /c flag when running a command using the cmd.exe. This could be a sign of obfuscation of a fat finger problem (typo by the developer)."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "cmd.exe/c" or ProcessCommandLine contains "\\cmd/c" or ProcessCommandLine contains "\"cmd/c" or ProcessCommandLine contains "cmd.exe/k" or ProcessCommandLine contains "\\cmd/k" or ProcessCommandLine contains "\"cmd/k" or ProcessCommandLine contains "cmd.exe/r" or ProcessCommandLine contains "\\cmd/r" or ProcessCommandLine contains "\"cmd/r") or (ProcessCommandLine contains "/cwhoami" or ProcessCommandLine contains "/cpowershell" or ProcessCommandLine contains "/cschtasks" or ProcessCommandLine contains "/cbitsadmin" or ProcessCommandLine contains "/ccertutil" or ProcessCommandLine contains "/kwhoami" or ProcessCommandLine contains "/kpowershell" or ProcessCommandLine contains "/kschtasks" or ProcessCommandLine contains "/kbitsadmin" or ProcessCommandLine contains "/kcertutil") or (ProcessCommandLine contains "cmd.exe /c" or ProcessCommandLine contains "cmd /c" or ProcessCommandLine contains "cmd.exe /k" or ProcessCommandLine contains "cmd /k" or ProcessCommandLine contains "cmd.exe /r" or ProcessCommandLine contains "cmd /r")) and (not(((ProcessCommandLine in~ ("cmd.exe /c") or ProcessCommandLine contains "AppData\\Local\\Programs\\Microsoft VS Code\\resources\\app\\node_modules" or ProcessCommandLine endswith "cmd.exe/c .") or (ProcessCommandLine contains "cmd.exe /c " or ProcessCommandLine contains "cmd /c " or ProcessCommandLine contains "cmd.exe /k " or ProcessCommandLine contains "cmd /k " or ProcessCommandLine contains "cmd.exe /r " or ProcessCommandLine contains "cmd /r "))))
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
}